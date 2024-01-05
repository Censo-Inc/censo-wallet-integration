import CensoWalletIntegration, {CensoWalletConfig, Language} from '../src/index.js'
import { mnemonicToEntropy } from "bip39";

const sdk = new CensoWalletIntegration(
  new CensoWalletConfig(
    process.env.CENSO_API_URL ?? 'https://api.censo.co',
    process.env.CENSO_API_VERSION ?? 'v1',
    process.env.CENSO_LINK_SCHEME ?? 'censo-main',
    process.env.CENSO_LINK_VERSION ?? 'v1'
  )
);

const seedPhrase = mnemonicToEntropy(
  'grocery crush fantasy pulse struggle brain federal equip remember figure lyrics afraid tape ugly gold yard way isolate drill lawn daughter either supply student'
);
console.log("seedPhrase = ", seedPhrase)
function onFinished(success: boolean) {
  console.log(`session finished: ${success}`)
}

sdk.initiate(onFinished).then(session => {
      // after the session is established, the SDK will execute this callback expecting it to return the seed phrase in binary form
      // this will be immediately encrypted and sent to the user's Censo app for them to add
      async function onConnected() {
          return session.phrase(
            seedPhrase,
            Language.English, // seed phrase language; optional, defaults to english
            "my phrase", // phrase label; optional
          )
      }

      // connectionLink is a deeplink to the censo app. Give it to the user as a link and/or a QR code.
      // The user must already be set up on Censo. This will then establish the connection and provide
      // the user's encryption key which will be used to securely transfer the seed phrase to the Censo
      // app. After this has been completed, the `onFinished` callback will be called with a success
      // boolean and the session will be over.
      session.connect(onConnected).then(connectionLink => {
          console.log(connectionLink)
        }
      )
  }
)
