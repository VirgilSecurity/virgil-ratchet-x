# Virgil Security Ratchet Objective-C/Swift SDK

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-ratchet-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-ratchet-x)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilSDKRatchet.svg)](https://cocoapods.org/pods/VirgilSDKRatchet)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Platform](https://img.shields.io/cocoapods/p/VirgilSDKRatchet.svg?style=flat)](https://cocoapods.org/pods/VirgilSDKRatchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Initialization](#initialization) | [Chat Example](#chat-example) | [Register Users](#register-users) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of services and open source libraries for adding security to any application.
Virgil Security is presenting an implementation of the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) algorithm, which is used by parties to exchange encrypted messages based on a shared secret key. The implementation includes:
- **[Virgil Perfect Forward Secrecy (PFS) service][_pfs_service]** – a standalone web-service that is dedicated to managing one-time keys and long-time keys that are based on their Identity Public Keys (public keys that are contained in user cards published on Virgil Cards service);
- **Ratchet SDK** – interacts with PFS service for publishing and managing one-time keys and long-time keys and interacts with Virgil Cards service for retrieving user's indentity cards which the OTK and LTK are based on. The parties derive new keys for every Double Ratchet message so that previous private keys cannot be calculated from new ones. The parties that participate in the communication also send Diffie-Hellman public values attached to their messages. The results of Diffie-Hellman calculations are mixed into the derived keys so that the new private keys cannot be calculated from the previous ones.

Following this, the parties will use the Double Ratchet SDK to initialize chat session and send and receive encrypted messages. And as a result, by adding Virgil Perfect Forward Secrecy (PFS) to your encrypted communication you prevent a possibly compromised user's long time private key (private key) from affecting the confidentiality of past communications.


# SDK Features
- communicate with [Virgil PFS Service][_pfs_service]
- manage users' OTK and LTK keys
- use Virgil [Crypto library][_virgil_crypto]

## Installation

Virgil SDK Ratchet is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods. Also in this guide, you find one more package called VirgilCrypto (Virgil Crypto Library) that is used by the Virgil SDK Ratchet to perform cryptographic operations.

All frameworks are available for:
- iOS 9.0+
- macOS 10.10+
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

## Initialization

Make sure that you have already registered at the [Virgil Dashboard][_dashboard] and created an E2EE V5 application.

Before the chat initialization, each user must have a Virgil Card on Virgil Card Service.
If you have no Virgil Card yet, you can easily create it with our [guide](#register-users).


## Chat Example

To begin communicating with PFS service, every user must run the initialization:

```swift
import VirgilSDKRatchet

let context = SecureChatContext(identity: card.identity,
                                identityCardId: card.identifier,
                                identityPrivateKey: keyPair.privateKey,
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

Then Sender establishes a secure PFS conversation with Receiver, encrypts and sends the message:

```swift
import VirgilSDKRatchet

// prepare a message
let messageToEncrypt = "Hello, Bob!"

let session: SecureSession

if let existingSession = secureChat.existingSession(withParticpantIdentity: bobCard.identity) {
    session = existingSession
} else {
    // start new session with recipient if session wasn't initialized yet
    session = try! secureChat.startNewSessionAsSender(receiverCard: bobCard).startSync().getResult()
}

let ratchetMessage = try! session.encrypt(string: messageToEncrypt)

let encryptedMessage = ratchetMessage.serialize()
```

Receiver decrypts the incoming message using the conversation he has just created:

```swift
import VirgilCryptoRatchet
import VirgilSDKRatchet

let ratchetMessage = try! RatchetMessage.deserialize(input: encryptedMessage)

let session: SecureSession

if let existingSession = secureChat.existingSession(withParticpantIdentity: aliceCard.identity) {
    session = existingSession
} else {
    // start new session with sender if session wasn't initialized yet
    session = try! secureChat.startNewSessionAsReceiver(senderCard: aliceCard, ratchetMessage: ratchetMessage)
}

let decryptedMessage = try! session.decryptString(from: ratchetMessage)
```

With the open session, which works in both directions, Sender and Receiver can continue PFS-encrypted communication.

## Register Users

In Virgil every user has a **Private Key** and is represented with a **Virgil Card**, which contains a Public Key and user's identity.

Using Identity Cards, we generate special Cards that have their own life-time:
* **One-time Key (OTK)**
* **Long-time Key (LTK)**

For each session you can use new OTK and delete it after session is finished.

To create user's Virgil Cards, you can use the following code from [this guide](https://developer.virgilsecurity.com/docs/how-to/public-key-management/v5/create-card).

## Docs

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [PFS Service API reference][_pfs_service]
* [How to publish user's cards](https://developer.virgilsecurity.com/docs/how-to/public-key-management/v5/create-card)

To find more examples how to use Virgil Products, take a look at [SWIFT SDK documentation](https://github.com/VirgilSecurity/virgil-sdk-x/blob/v5/README.md).

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).


[_pfs_service]: https://developer.virgilsecurity.com/docs/api-reference/pfs-service/v4
[_sdk_x]: https://github.com/VirgilSecurity/virgil-sdk-x/tree/v5

[_dashboard]: https://dashboard.virgilsecurity.com/
[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_pfs_reference_api]: https://developer.virgilsecurity.com/docs/references/perfect-forward-secrecy
[_use_cases]: https://developer.virgilsecurity.com/docs/use-cases
[_use_case_pfs]:https://developer.virgilsecurity.com/docs/swift/use-cases/v4/perfect-forward-secrecy

