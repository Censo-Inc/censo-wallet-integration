import type {JsonWebKey} from "crypto";

import base58 from "bs58";
import axios from 'axios';
import { AxiosHeaders } from "axios";
import keyutils from 'js-crypto-key-utils';
import elliptic from 'js-crypto-ec';
import sha256 from 'js-sha256';
import { Buffer } from 'buffer';

async function importSubtle(): Promise<any> {
  if (globalThis.crypto) {
    const { subtle } = globalThis.crypto
    return subtle
  } else {
    const crypto = await import("crypto")
    return crypto.webcrypto.subtle
  }
}

const subtle = await importSubtle()

export class Session {
  private readonly name: string
  private readonly apiUrl: string
  private readonly apiVersion: string
  private readonly linkScheme: string
  private readonly linkVersion: string
  private readonly onFinished: (success: boolean) => void;
  private channelKeyPair: CryptoKeyPair|null = null
  private authKeyPair: CryptoKeyPair|null = null
  private keyPairsCreatedAt: Date|null = null
  private checkConnectedInterval: NodeJS.Timeout|null = null
  private ownerDeviceKey: CryptoKey|null = null
  private finished: boolean

  constructor(name: string, apiUrl: string, apiVersion: string, linkScheme: string, linkVersion: string, onFinished: (success: boolean) => void) {
    this.name = name
    this.apiUrl = apiUrl
    this.apiVersion = apiVersion
    this.linkScheme = linkScheme
    this.linkVersion = linkVersion
    this.onFinished = onFinished
    this.finished = false
  }

  private ECDSA_SIGN_VERIFY = {"name": "ECDSA", "hash": "SHA-256"}
  private EC_KEY_GENERATE_IMPORT = {"name": "ECDSA", "namedCurve": "P-256"}

   setKeypairs = (): Promise<Session> => {
    return Promise.all([
      subtle.generateKey(
        this.EC_KEY_GENERATE_IMPORT,
        true,
        ["sign", "verify"]
      ),
      subtle.generateKey(
        this.EC_KEY_GENERATE_IMPORT,
        true,
        ["sign", "verify"]
      )]).then(([channelKeyPair, authKeyPair]) => {
        this.channelKeyPair = channelKeyPair
        this.authKeyPair = authKeyPair
        this.keyPairsCreatedAt = new Date()
        return this
      }
    )
  }

  private authHeaders = async (method: string, path: string, body: string): Promise<AxiosHeaders> => {
    const authKey = await subtle.exportKey("raw", this.authKeyPair!.publicKey)
    const now = new Date()
    const dataToSign = `${method}/${this.apiVersion}/${path}${btoa(body)}${now.toISOString()}`
    const signature = await subtle.sign(this.ECDSA_SIGN_VERIFY, this.authKeyPair!.privateKey, Buffer.from(dataToSign))
    return new AxiosHeaders({
      "Authorization": `signature ${Buffer.from(signature).toString('base64')}`,
      "X-Censo-Device-Public-Key": base58.encode(new Uint8Array(authKey)),
      "X-Censo-Timestamp": now.toISOString()
    })
  }

  private derToP1363 = (derSignature: Buffer): Buffer|undefined => {
    // Remove header of 48 + 1-byte length
    if (derSignature[0] === 48) {
      derSignature = derSignature.slice(2)

      // should be 1 byte with value 2, followed by 1 byte with the length of R
      if (derSignature[0] === 2) {
        const rLength = derSignature[1]
        const r: Buffer = derSignature.slice(2, 2 + rLength)
        // then should be another byte with value 2, followed by 1 byte with the length of S
        if (derSignature[2 + rLength] === 2) {
          const sLength = derSignature[2 + rLength + 1]
          const s: Buffer = derSignature.slice(2 + rLength + 2, 2 + rLength + 2 + sLength)
          const truncateTo32 = (x: Buffer): Buffer => x.length === 33 && x[0] === 0 ? x.slice(1) : x
          return Buffer.concat([truncateTo32(r), truncateTo32(s)])
        }
      }
    }
  }

  private checkConnected = async (): Promise<boolean> => {
    const channel = await subtle.digest({"name": "SHA-256"}, await subtle.exportKey("raw", this.channelKeyPair?.publicKey!))
    const encodedChannel = this.base64ToBase64Url(Buffer.from(channel).toString('base64'))
    const result = await axios.get(
      `${this.apiUrl}/${this.apiVersion}/import/${encodedChannel}`,
      {"headers": await this.authHeaders("GET", `import/${encodedChannel}`, "")}
    )
    if (result.status == 200) {
      if (result.data['importState']['type'] == 'Accepted') {
        this.ownerDeviceKey = await subtle.importKey(
          "raw",
          base58.decode(result.data['importState']['ownerDeviceKey']),
          this.EC_KEY_GENERATE_IMPORT,
          true,
          ["verify"]
        )
        const derSignature = Buffer.from(result.data['importState']['ownerProof'], 'base64')
        const ownerSignature = this.derToP1363(derSignature)
        if (ownerSignature === undefined) {
          console.log("Could not convert signature from DER to P1363 format")
          throw new Error("Could not verify user")
        } else {
          const publicKey = await subtle.exportKey("raw", this.channelKeyPair!.publicKey)
          const verified = await subtle.verify(this.ECDSA_SIGN_VERIFY, this.ownerDeviceKey, ownerSignature, publicKey)
          if (!verified) {
            throw new Error("Could not verify user")
          }
          return verified
        }
      }
    } else if (result.status >= 400 && result.status < 500) {
      throw new Error("Connection to Censo terminated or timed-out")
    }
    return false
  }

  connect = async (onConnected: () => void): Promise<string> => {
    this.checkConnectedInterval = setInterval(() => {
      // check if session is expired (10 minutes after keypair creation)
      if (new Date().getTime() - (this.keyPairsCreatedAt?.getTime() ?? 0) > 10 * 60 * 1000) {
        this.cancel()
      } else {
        try {
          this.checkConnected().then(async (completed) => {
            if (completed) {
              if (this.checkConnectedInterval != null) {
                clearInterval(this.checkConnectedInterval)
              }
              await onConnected()
            }
          })
        } catch (e) {
          console.log("unable to connect", e)
          if (this.checkConnectedInterval != null) {
            clearInterval(this.checkConnectedInterval)
          }
          this.finished = true
          this.onFinished(false)
        }
      }
    }, 500)

    const publicKeyBytes = await subtle.exportKey("raw", this.channelKeyPair!.publicKey)
    const dateInMillis = this.keyPairsCreatedAt!.getTime()
    const dateInMillisAsBytes = (new TextEncoder()).encode(dateInMillis.toString())
    const nameBuffer = Buffer.from(this.name)
    const nameHash = await subtle.digest({"name": "SHA-256"}, nameBuffer)
    const dataToSign = new Uint8Array(dateInMillisAsBytes.byteLength + nameHash.byteLength)
    dataToSign.set(new Uint8Array(dateInMillisAsBytes), 0)
    dataToSign.set(new Uint8Array(nameHash), dateInMillisAsBytes.byteLength)
    const signature = await subtle.sign(this.ECDSA_SIGN_VERIFY, this.channelKeyPair!.privateKey, dataToSign)
    const encodedSignature = this.base64ToBase64Url(Buffer.from(signature).toString('base64'))
    const encodedName = this.base64ToBase64Url(nameBuffer.toString('base64'))
    const verified = await subtle.verify(this.ECDSA_SIGN_VERIFY, this.channelKeyPair!.publicKey, signature, dataToSign)
    if (verified) {
      return `${this.linkScheme}://import/${this.linkVersion}/${base58.encode(new Uint8Array(publicKeyBytes))}/${dateInMillis}/${encodedSignature}/${encodedName}`
    } else {
      return "UNVERIFIED"
    }
  }

  private base64ToBase64Url = (base64: string): string => {
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/m, "")
  }

  private base64UrlToBase64 = (base64Url: string): string => {
    return base64Url.replace(/-/g, "+").replace(/_/g, "/")
  }

  private kdf2 = (shared: Uint8Array, iv: Uint8Array): Uint8Array => {
    const hasher = sha256.sha256.create()
    hasher.update(shared)
    const counter = new Uint8Array([0, 0, 0, 1])
    hasher.update(counter)
    hasher.update(iv)
    return new Uint8Array(hasher.digest())
  }

  cancel = () => {
    if (this.checkConnectedInterval != null) {
      clearInterval(this.checkConnectedInterval)
    }
    this.finished = true
    this.onFinished(false)
  }

  phrase = async (binaryPhrase: string, language?: Language, label?: string) => {
    if (this.finished) {
      throw new Error("Session is finished")
    }
    const ownerKey = await subtle.exportKey("raw", this.ownerDeviceKey!)
    const message = JSON.stringify({
      binaryPhrase: binaryPhrase,
      language: language ?? Language.English,
      label: label ?? ""
    })

    const publicKey = new keyutils.Key('oct', new Uint8Array(ownerKey), {namedCurve: "P-256"})
    const publicKeyJwk = await publicKey.jwk as JsonWebKey
    const ephemeralKeyPair = await elliptic.generateKey("P-256")

    const sharedKey = await elliptic.deriveSecret(publicKeyJwk, ephemeralKeyPair.privateKey)

    let kdfSalt = new Uint8Array(65)
    kdfSalt[0] = 4
    Buffer.from(Buffer.from(this.base64UrlToBase64(ephemeralKeyPair.publicKey.x!), 'base64')).forEach((byte, ix) => kdfSalt[ix + 1] = byte)
    Buffer.from(Buffer.from(this.base64UrlToBase64(ephemeralKeyPair.publicKey.y!), 'base64')).forEach((byte, ix) => kdfSalt[ix + 33] = byte)
    const derivedKey = Buffer.from(this.kdf2(Buffer.from(sharedKey), kdfSalt))

    const encryptedData = await subtle.encrypt({
        "name": "AES-GCM",
        "iv": derivedKey.subarray(16, 32)
      },
      await subtle.importKey("raw", Buffer.from(derivedKey.subarray(0, 16)), {"name": "AES-GCM"}, true, ["encrypt"]),
      new Uint8Array(Buffer.from(message))
    )
    let expandedData = new Uint8Array(65 + encryptedData.byteLength)
    kdfSalt.slice(0, 65).forEach((byte, ix) => expandedData[ix] = byte)
    new Uint8Array(encryptedData).forEach((byte, ix) => expandedData[65 + ix] = byte)
    const body = JSON.stringify(
      {
        'encryptedData': Buffer.from(expandedData).toString('base64')
      }
    )
    const channel = await subtle.digest({"name": "SHA-256"}, await subtle.exportKey("raw", this.channelKeyPair?.publicKey!))
    const encodedChannel = this.base64ToBase64Url(Buffer.from(channel).toString('base64'))
    const result = await axios.post(`${this.apiUrl}/${this.apiVersion}/import/${encodedChannel}/encrypted`, body, {
      'headers': await this.authHeaders("POST", `import/${encodedChannel}/encrypted`, body)
    })
    this.finished = true
    if (result.status == 200) {
      this.onFinished(true)
    } else {
      console.log("Could not export phrase", result.status)
      this.onFinished(false)
    }
  }
}

export enum Language {
  English = 1,
  Spanish = 2,
  French = 3,
  Italian = 4,
  Portugese = 5,
  Czech = 6,
  Japanese = 7,
  Korean = 8,
  ChineseTraditional = 9,
  ChineseSimplified = 10,
}

export class CensoWalletConfig {
  apiUrl: string
  apiVersion: string
  linkScheme: string
  linkVersion: string
  constructor(apiUrl?: string, apiVersion?: string, linkScheme?: string, linkVersion?: string) {
    this.apiUrl = apiUrl ?? 'https://api.censo.co'
    this.apiVersion = apiVersion ?? 'v1'
    this.linkScheme = linkScheme ?? 'censo-main'
    this.linkVersion = linkVersion ?? 'v1'
  }
}

export default class CensoWalletIntegration {
  private config: CensoWalletConfig
  constructor(config?: CensoWalletConfig) {
    this.config = config ?? new CensoWalletConfig()
  }

  initiate = (onFinished: (success: boolean) => void): Promise<Session> => {
    const name = (typeof window !== "undefined" ? window.location.hostname : "UNKNOWN")
    const session = new Session(name, this.config.apiUrl, this.config.apiVersion, this.config.linkScheme, this.config.linkVersion, onFinished)
    return session.setKeypairs()
  }
}
