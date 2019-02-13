# Virgil Security Ratchet Objective-C/Swift SDK

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-ratchet-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-ratchet-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilSDKRatchet.svg)](https://cocoapods.org/pods/VirgilSDKRatchet)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilSDKRatchet.svg?style=flat)](http://cocoadocs.org/docsets/VirgilSDKRatchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Initialization](#initialization) | [Chat Example](#chat-example) | [Register Users](#register-users) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application.

The Virgil Ratchet SDK allows developers to 

# SDK Features
- communicate with [Virgil ____ Service][]
- manage users' OTC and LTC cards
- use Virgil [Crypto library][_virgil_crypto]

## Installation

> Virgil SWIFT Ratchet SDK is suitable only for Client Side.

The Virgil Ratchet is provided as a package.

### COCOAPODS

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate Virgil Ratchet SDK into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
-
```

Then, run the following command:

```bash
$ pod install
```

### Carthage

Carthage is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.
You can install Carthage with Homebrew using the following command:
```
$ brew update
$ brew install carthage
```
To integrate Virgil Ratchet SDK (?) into your Xcode project using Carthage, perform following steps:
* Create an empty file with name Cartfile in your project's root folder, that lists the frameworks you’d like to use in your project.
* Add the following line to your Cartfile:

```
-
```

* Run carthage update. This will fetch dependencies into a Carthage/Checkouts folder inside your project's folder, then build each one or download a pre-compiled framework.
* On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add each framework you want to use from the Carthage/Build folder inside your project's folder.
* On your application targets’ “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase”. Create a Run Script in which you specify your shell (ex: /bin/sh), add the following contents to the script area below the shell:

```
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
-
```

## Initialization

> Virgil SWIFT Ratchet SDK is suitable only for Client Side. 

Make sure that you have already registered at the [Developer Dashboard][_dashboard] and created your application.

To initialize the SWIFT Ratchet SDK at the __Client Side__, you need only the __Access Token__ created for a client at [Dashboard][_dashboard].
The Access Token helps to authenticate client's requests.

```swift
let virgil = VSSVirgilApi(token: "[YOUR_ACCESS_TOKEN_HERE]")
```


## Chat Example

Before chat initialization, each user must have a Virgil Card on Virgil Card Service.
If you have no Virgil Card yet, you can easily create it with our [guide](#register-users).

To begin communicating with PFS technology, every user must run the initialization:

```swift
// initialize Virgil crypto instance
// enter User's credentials to create OTC and LTC Cards
let secureChatPreferences = SecureChatPreferences (
    crypto: "[CRYPTO]", // (e.g. VSSCrypto())
    identityPrivateKey: bobKey.privateKey,
    identityCard: bobCard.card!,
    accessToken: "[YOUR_ACCESS_TOKEN_HERE]")

// this class performs all PFS-technology logic: creates LTC and OTL Cards, publishes them, etc.
self.secureChat = SecureChat(preferences: secureChatPreferences)

try self.secureChat.initialize()

// the method is periodically called to:
// - check availability of user's OTC Cards on the service
// - add new Cards till their quantity reaches the number (100) noted in current method
self.secureChat.rotateKeys(desiredNumberOfCards: 100) { error in
    //...
}
```

Then Sender establishes a secure PFS conversation with Receiver, encrypts and sends the message:

```swift
func sendMessage(forReceiver receiver: User, message: String) {
    guard let session = self.chat.activeSession(
        withParticipantWithCardId: receiver.card.identifier) else {
        // start new session with recipient if session wasn't initialized yet
        self.chat.startNewSession(
            withRecipientWithCard: receiver.card) { session, error in

            guard error == nil, let session = session else {
                // Error handling
                return
            }

            // get an active session by recipient's Card ID
            self.sendMessage(forReceiver: receiver,
                usingSession: session, message: message)
        }
        return
    }

    self.sendMessage(forReceiver: receiver,
        usingSession: session, message: message)
}

func sendMessage(forReceiver receiver: User,
    usingSession session: SecureSession, message: String) {
    let ciphertext: String
    do {
        // encrypt the message using previously initialized session
        ciphertext = try session.encrypt(message)
    }
    catch {
        // Error handling
        return
    }

    // send a cipher message to recipient using your messaging service
    self.messenger.sendMessage(
        forReceiverWithName: receiver.name, text: ciphertext)
}
```

Receiver decrypts the incoming message using the conversation he has just created:

```swift
func messageReceived(fromSenderWithName senderName: String, message: String) {
    guard let sender = self.users.first(where: { $0.name == senderName }) else {
        // User not found
        return
    }

    self.receiveMessage(fromSender: sender, message: message)
}

func receiveMessage(fromSender sender: User, message: String) {
    do {
        let session = try self.chat.loadUpSession(
            withParticipantWithCard: sender.card, message: message)

        // decrypt message using established session
        let plaintext = try session.decrypt(message)

        // show a message to the user
        print(plaintext)
    }
    catch {
        // Error handling
    }
}
```

With the open session, which works in both directions, Sender and Receiver can continue PFS-encrypted communication.

Take a look at our [Use Case][_use_case_pfs] to see the whole scenario of the PFS-encrypted communication.


## Register Users

In Virgil every user has a **Private Key** and represented with a **Virgil Card (Identity Card)**, which contains a Public Key and user's identity.

Using Identity Cards, we generate special Cards that have their own life-time:
* **One-time Card (OTC)**
* **Long-time Card (LTC)**

For each session you can use new OTC and delete it after session is finished.

To create user's Identity Virgil Cards, use the following code:

```swift
// generate a new Virgil Key
let aliceKey = virgil.keys.generateKey()

// save the Virgil Key into storage
try! aliceKey.store(withName: @"[KEY_NAME]",
  password: @"[KEY_PASSWORD]")

// create identity for Alice
let aliceIdentity = virgil.identities.
  createUserIdentity(withValue: "alice", type: "name")

// create a Virgil Card
var aliceCard = try! virgil.cards.
  createCard(with: aliceIdentity, ownerKey:aliceKey)

// export a Virgil Card to string
let exportedCard = aliceCard.exportData()

// transmit the Virgil Card to the server and receive response
let cardData = TransmitToServer(exportedCard)
```

When Virgil Card created, sign and publish it with Application Private Virgil Key at the server side.

SWIFT is not supported for publishing Virgil Cards on Virgil Services.
We recommend using one of the supported languages with this [guide](https://developer.virgilsecurity.com/docs/go/how-to/public-key-management/v4/create-card).

## Docs

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* -
* -

To find more examples how to use Virgil Products, take a look at [SWIFT SDK documentation](https://github.com/VirgilSecurity/virgil-sdk-x/blob/v5/README.md).

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).



[_sdk_x]: https://github.com/VirgilSecurity/virgil-sdk-x/tree/v5

[_dashboard]: https://dashboard.virgilsecurity.com/
[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_pfs_reference_api]: https://developer.virgilsecurity.com/docs/references/perfect-forward-secrecy
[_use_cases]: https://developer.virgilsecurity.com/docs/use-cases
[_use_case_pfs]:https://developer.virgilsecurity.com/docs/swift/use-cases/v4/perfect-forward-secrecy

