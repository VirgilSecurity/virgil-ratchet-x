# Virgil Security Ratchet Objective-C/Swift SDK

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-ratchet-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-ratchet-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilSDKRatchet.svg)](https://cocoapods.org/pods/VirgilSDKRatchet)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilSDKRatchet.svg?style=flat)](https://cocoapods.org/pods/VirgilSDKRatchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Register Users](#register-users) | [Peer-to-peer Chat Example](#peer-to-peer-chat-example) | [Group Chat Example](#group-chat-example) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of services and open source libraries for adding security to any application.
Virgil Security is presenting an implementation of the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) algorithm, which is used by parties to exchange encrypted messages based on a shared secret key. The implementation includes:
- **Virgil Perfect Forward Secrecy (PFS) service** – a standalone web-service designed to manage one-time keys and long-term keys that are based on their Identity Public Keys (public keys in user cards published on Virgil Cards service);
- **Ratchet SDK** – interacts with PFS service in order to publish and manage one-time keys (OTK) and long-term keys (LTK) and interacts with Virgil Cards service to retrieve user's identity cards which the OTK and LTK are based on. The parties derive new keys for every Double Ratchet message so that previous private keys cannot be calculated from new ones. The parties that participate in the communication also send Diffie-Hellman public values attached to their messages. The results of Diffie-Hellman calculations are mixed into the derived keys so that the new private keys cannot be calculated from the previous ones.

Following this, the parties will use the Double Ratchet SDK to initialize chat session, send and receive encrypted messages. And as a result by adding Virgil Perfect Forward Secrecy (PFS) to your encrypted communication, you prevent a possibly compromised user's long-term private key from affecting the confidentiality of past communications.


# SDK Features
- communicate with Virgil PFS Service
- manage users' one-time keys (OTK) and long-term keys (LTK)
- enable group chat encryption

## Installation

Virgil SDK Ratchet is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods. Also in this guide, you find two more packages called VirgilCrypto (Virgil Crypto Library) that is used by the Virgil SDK Ratchet to perform cryptographic operations and VirgilSDK.

All frameworks are available for:
- iOS 9.0+
- macOS 10.11+
- tvOS 9.0+
- watchOS 2.0+

### COCOAPODS

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate Virgil Ratchet SDK into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
target '<Your Target Name>' do
use_frameworks!

pod 'VirgilSDKRatchet', '~> 0.1.0'
end
```

Then, run the following command:

```bash
$ pod install
```

### Carthage

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.

You can install Carthage with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate VirgilSDKRatchet into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/virgil-ratchet-x" ~> 0.1.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilSDKRatchet
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCrypto
 - VirgilCryptoFoundation
 - VirgilCryptoRatchet
 - VSCCommon
 - VSCFoundation
 - VSCRatchet

On your application targets’ “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase.” Create a Run Script in which you specify your shell (ex: */bin/sh*), add the following contents to the script area below the shell:

```bash
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
$(SRCROOT)/Carthage/Build/iOS/VirgilSDKRatchet.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoAPI.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoFoundation.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoRatchet.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCommon.framework
$(SRCROOT)/Carthage/Build/iOS/VSCFoundation.framework
$(SRCROOT)/Carthage/Build/iOS/VSCRatchet.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
 - VirgilSDKRatchet
 - VirgilSDK
 - VirgilCryptoAPI
 - VirgilCrypto
 - VirgilCryptoFoundation
 - VirgilCryptoRatchet
 - VSCCommon
 - VSCFoundation
 - VSCRatchet

Additionally, you'll need to copy debug symbols for debugging and crash reporting on macOS.

On your application target’s “Build Phases” settings tab, click the “+” icon and choose “New Copy Files Phase”.
Click the “Destination” drop-down menu and select “Products Directory”. For each framework, drag and drop corresponding dSYM file.

## Register Users

Make sure that you have already registered at the [Virgil Dashboard][_dashboard] and created an E2EE V5 application.

Besides from registering on your own server, your users must also be registered at Virgil Cloud. If they already are, you can skip this step and proceed to the next one.

At Virgil every user has a `Private Key` on their device and is represented with a `Virgil Card` which contains a `Public Key` and user's `identity`. `Virgil Card` is a synonym to `Identity Card` in context of Virgil Services, and has an unlimited life-time.

In order to register your users at Virgil Cloud (i.e. create and publish their `Identity Cards`), you'll need to go through the following steps:
- Set up your backend for generating JWT in order to provide your service and users with access to Virgil Cloud;
- Set up you client side for authenticating users on Virgil Cloud;
- Set up Cards Manager on your client side to generate and publish `Identity Cards` on Virgil Cards Service.

You can use [this guide](https://developer.virgilsecurity.com/docs/how-to/public-key-management/v5/create-card) for the steps described above (you don't need to install Virgil SDK and Virgil Crypto if you've already installed Virgil Ratchet SDK).


### Initialize SDK

To begin communicating with PFS service and establish secure session, each user must run the initialization. In order to do that, you need the Receiver's public key (identity card) from Virgil Cloud and Sender's private key from their local storage:

```swift
import VirgilSDKRatchet

let context = SecureChatContext(identityCard: card,
                                identityKeyPair: keyPair,
                                accessTokenProvider: provider)

let secureChat = try! SecureChat(context: context)

secureChat.rotateKeys().start { result in
    switch result {
    // Keys were rotated
    case .success(let rotationLog): break
    // Error occured
    case .failure(let error): break
    }
}
```

During the initialization process, using Identity Cards and `rotateKeys` method we generate special Keys that have their own life-time:

* **One-time Key (OTK)** - each time someone wants to create session with user, single one-time key is obtained and discarded from the server.
* **Long-term Key (LTK)** - rotated periodically (daily or monthly based on the application developer's security considerations) and is signed with the Identity Private Key.

## Peer-to-peer Chat Example
In this section you'll find out how to build a peer-to-peer chat using Virgil Ratchet SDK.

### Send initial encrypted message
Let's assume Alice wants to start communication with Bob and wants to send the first message:
- first, Alice has to create a new chat session by running the `startNewSessionAsSender` function and specify Bob's Identity Card
- then, Alice encrypts the initial message using the `encrypt` SDK function
- finally, Alice has to store generated session locally. The Ratchet SDK doesn't store and update sessions itself. That's why you need to use the `storeSession` SDK function for storing the chat sessions.

```swift
import VirgilSDKRatchet

// prepare a message
let messageToEncrypt = "Hello, Bob!"

// start new secure session with Bob
let session = try! secureChat.startNewSessionAsSender(receiverCard: bobCard).startSync().getResult()

let ratchetMessage = try! session.encrypt(string: messageToEncrypt)

try! secureChat.storeSession(session)

let encryptedMessage = ratchetMessage.serialize()
```

**Important**: Also, you need to store session after operations that change the session's state (encrypt, decrypt), therefore if the session already exists in storage, it will be overwritten

### Decrypt the initial message

After Alice generated and stored the chat session, Bob also has to:
- start the chat session by running the `startNewSessionAsReceiver` function
- decrypt the encrypted message using the using the `decrypt` SDK function

```swift
import VirgilCryptoRatchet
import VirgilSDKRatchet

let ratchetMessage = try! RatchetMessage.deserialize(input: encryptedMessage)

let session = try! secureChat.startNewSessionAsReceiver(senderCard: aliceCard, ratchetMessage: ratchetMessage)

let decryptedMessage = try! session.decryptString(from: ratchetMessage)

try! secureChat.storeSession(session)
```

**Important**: Also, you need to store session after operations that change the session's state (encrypt, decrypt), therefore if the session already exists in storage, it will be overwritten

### Encrypt and decrypt messages

#### Encrypting messages
In order to encrypt further messages, use the `encrypt` function. This function allows you to encrypt data and strings.

> You also need to use message serialization to transfer encrypted messages between users. And do not forget to update session in storage as its state is changed on every encrypt operation!

- Use the following code-snippets to encrypt strings:

```swift
let session = secureChat.existingSession(withParticpantIdentity: bobCard.identity)!

let message = try! session.encrypt(string: "Hello, Bob!")

try! secureChat.storeSession(session)

let messageData = message.serialize()
// Send messageData to Bob
```

- Use the following code-snippets to encrypt data:

```Swift
let session = secureChat.existingSession(withParticpantIdentity: bobCard.identity)!

let message = try! session.encrypt(data: data)

try! secureChat.storeSession(session)

let messageData = message.serialize()
// Send messageData to Bob
```

#### Decrypting Messages
In order to decrypt messages, use the `decrypt` function. This function allows you to decrypt data and strings.

> You also need to use message serialization to transfer encrypted messages between users. And do not forget to update session in storage as its state is changed on every decrypt operation!

- Use the following code-snippets to decrypt strings:

```Swift
let session = secureChat.existingSession(withParticpantIdentity: aliceCard.identity)!

let message = try! RatchetGroupMessage.deserialize(input: messageData)

let decryptedMessage = try! session.decryptString(from: ratchetMessage)

try! secureChat.storeSession(session)
```
- Use the following code-snippets to decrypt data:

```swift
let session = secureChat.existingSession(withParticpantIdentity: aliceCard.identity)

let message = try! RatchetGroupMessage.deserialize(input: messageData)

let decryptedMessage = try! session.decryptData(from: ratchetMessage)

try! secureChat.storeSession(session)
```


## Group Chat Example
In this section you'll find out how to build a group chat using the Virgil Ratchet SDK.

### Create Group Chat Ticket
Let's assume Alice wants to start group chat with Bob and Carol. First of all, you have to create a new group session ticket by running the `startNewGroupSession` method. This ticket holds shared root key for further group encryption, therefore it should be encrypted and transmitted to other group participants. Every group chat should have unique 32-byte session identifier, we recommend to tie this identifier to your unique transport channel id. If your channel id is not 32-byte you can use SHA-256 to derive session id from it.

```Swift
// Create transport channel according to your app logic and get session id from it
let sessionId = Data(hexEncodedString: "7f4f96cedbbd192ddeb08fbf3a0f5db0da14310c287f630a551364c54864c7fb")!

let ticket = try! secureChat.startNewGroupSession(sessionId: sessionId)
```

### Start Group Chat Session
Now, you have to start the group session by running the `startGroupSession` function. This function requires specifying the group chat session ID, the receivers' Virgil Cards and ticket.

```Swift
let receiverCards = try! cardManager.searchCards(["Bob", "Carol"]).startSync().getResult()

let groupSession = try! secureChat.startGroupSession(with: receiverCards,
                                                     sessionId: sessionId,
                                                     using: ticket)
```

###  Store the Group Session
The Ratchet SDK doesn't store and update the group chat session itself. That's why you need to use the `storeGroupSession` SDK function for storing the chat sessions.

> Also, you need to store existing session after operations that change the session's state (encrypt, decrypt, setParticipants, updateParticipants), therefore if the session already exists in storage, it will be overwritten

```swift
try! secureChat.storeGroupSession(groupSession)
```

### Send the Group Ticket
Now, you have to provide the group chat ticket to other members.

- First of all, let's serialize the ticket

```Swift
let ticketData = ticket.serialize()
```

- For security reasons we can't send the unprotected ticket, because it contains unencrypted symmetric key. Therefore, we have to encrypt the serialized ticket for the receivers. The only proper secure way to do this, is to use peer-to-peer Double Ratchet sessions with each of participants to send the ticket.

```Swift
for card in receiverCards {
    guard let session = secureChat.existingSession(withParticpantIdentity: card.identity) else {
        // If you don't have session, see Peer-to-peer Chat Example on how to create it as Sender.
        return
    }

    let encryptedTicket = try! session.encrypt(data: ticketData).serialize()

    try! secureChat.storeGroupSession(groupSession)

    // Send ticket to receiver
}
```
- Now, use your application's business logic to share this encrypted ticket with the group chat participants.

### Join the Group Chat
Now, when we have the group chat created, other participants can join this chat using the group chat ticket.

- First, we have to decrypt the encrypted ticket

```Swift
guard let session = secureChat.existingSession(withParticpantIdentity: "Alice") else {
    // If you don't have session, see Peer-to-peer Chat Example on how to create it as Receiver.
    return
}

let encryptedTicketMessage = try! RatchetMessage.deserialize(input: encryptedTicket)

let ticketData = session.decryptData(from: encryptedTicketMessage)
```

- Then, use the `deserialize` function to deserialize the session ticket.

```Swift
let ticket = try! RatchetGroupMessage.deserialize(input: ticketData)
```
- Join the group chat by running the `startGroupSession` function and store session.

```Swift
let receiverCards = try! cardManager.searchCards(["Alice", "Bob"]).startSync().getResult()

let groupSession = try! secureChat.startGroupSession(with: receiverCards,
                                                     sessionId: sessionId,
                                                     using: ticket)

try! secureChat.storeGroupSession(groupSession)
```

### Encrypt and decrypt messages

#### Encrypting messages
In order to encrypt messages for the group chat, use the `encrypt` function. This function allows you to encrypt data and strings. You still need to use message serialization to transfer encrypted messages between users. And do not forget to update session in storage as its state is changed on every encrypt operation!

- Use the following code-snippets to encrypt strings:
```swift
let message = try! groupSession.encrypt(string: "Hello, Alice and Bob!")

try! secureChat.storeGroupSession(groupSession)

let messageData = message.serialize()
// Send messageData to receivers
```

- Use the following code-snippets to encrypt data:
```Swift
let message = try! groupSession.encrypt(data: data)

try! secureChat.storeGroupSession(groupSession)

let messageData = message.serialize()
// Send messageData to receivers
```

#### Decrypting Messages
In order to decrypt messages, use the `decrypt` function. This function allows you to decrypt data and strings. Do not forget to update session in storage as its state is changed on every encrypt operation!

- Use the following code-snippets to decrypt strings:
```Swift
let message = RatchetGroupMessage.deserialize(input: messageData)

let carolCard = receiversCard.first { $0.identity == "Carol" }!

let decryptedMessage = try! groupSession.decryptString(from: message, senderCardId: carolCard.identifier)

try! secureChat.storeGroupSession(groupSession)
```
- Use the following code-snippets to decrypt data:
```swift
let message = RatchetGroupMessage.deserialize(input: messageData)

let carolCard = receiversCard.first { $0.identity == "Carol" }!

let data = try! groupSession.decryptData(from: message, senderCardId: carolCard.identifier)

try! groupSession.storeGroupSession(groupSession)
```


## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).


[_sdk_x]: https://github.com/VirgilSecurity/virgil-sdk-x/tree/v5

[_dashboard]: https://dashboard.virgilsecurity.com/
[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto-c
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_use_cases]: https://developer.virgilsecurity.com/docs/use-cases
[_use_case_pfs]:https://developer.virgilsecurity.com/docs/swift/use-cases/v4/perfect-forward-secrecy
