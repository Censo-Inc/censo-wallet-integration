# Censo Wallet Integration SDK

The Censo Wallet Integration SDK allows you to easily empower any of your users who use the
Censo Seed Phrase Manager to save their seed phrases simply and securely.

The SDK will give you a deep link to the Censo app which you convey to the user, such as by
displaying it in a QR code. This link is only good for a few minutes, but you should take
care to show it only to the user and not store it. When their Censo app opens that deep link,
it will have established a secure communication channel to the SDK.

At this point, the SDK will trigger a callback where you provide the seed phrase (just as the
raw binary entropy) and the SDK will encrypt it and relay it to the user's Censo app, which
will display the seed phrase and allow the user to securely save it.

## Getting Started

### Installation

Install the Censo Seed Phrase Manager SDK using npm:

```bash
npm install @censo/wallet-integration
```

### Example Usage

First, load and instantiate the SDK:

```typescript
import CensoWalletIntegration from '@censo/wallet-integration';

const sdk = new CensoWalletIntegration();
```

Then, when a user wishes to export their seed phrase to their Censo app, initiate a session:

```typescript
function onFinished(success: boolean) {
  console.log(`session finished: ${success}`);
}

const session = await sdk.initiate(onFinished)
```

Set up a callback for after the user's Censo app has established the secure channel.

```typescript
const onConnected = async () => {
  // get the raw binary representation of the user's seed phrase here
  const seedPhraseEntropy = "..."
  return session.phrase(
    seedPhraseEntropy
  );
}
```

Then, just get the deep link and show it to the user:

```typescript
const deepLink = await session.connect(onConnected)

```

Once the user has received the seed phrase in their Censo app, the `onFinished` callback
will be called with `true`. If there's an error or timeout along the way, `onFinished`
will instead be called with `false`. In either case, the session will be closed at that
point.
