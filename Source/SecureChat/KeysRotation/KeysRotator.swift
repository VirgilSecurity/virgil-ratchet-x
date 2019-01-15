//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilCryptoApiImpl
import VirgilSDK

protocol KeysRotatorProtocol: class {
    func rotateKeysOperation() -> GenericOperation<Void>
}

class KeysRotator {
    private let crypto = VirgilCrypto(defaultKeyType: .EC_CURVE25519, useSHA256Fingerprints: false)
    private let identityPrivateKey: VirgilPrivateKey
    private let identityCardId: String
    private let orphanedOneTimeKeyTtl: TimeInterval
    private let longTermKeyTtl: TimeInterval
    private let outdatedLongTermKeyTtl: TimeInterval
    private let desiredNumberOfOneTimeKeys: Int
    private let longTermKeysStorage: LongTermKeysStorage
    private let oneTimeKeysStorage: OneTimeKeysStorage
    private let client: RatchetClientProtocol
    private let mutex = Mutex()

    init(identityPrivateKey: VirgilPrivateKey,
         identityCardId: String,
         orphanedOneTimeKeyTtl: TimeInterval = 24 * 60 * 60,
         longTermKeyTtl: TimeInterval = 5 * 24 * 60 * 60,
         outdatedLongTermKeyTtl: TimeInterval = 24 * 60 * 60,
         desiredNumberOfOneTimeKeys: Int = 100,
         longTermKeysStorage: LongTermKeysStorage,
         oneTimeKeysStorage: OneTimeKeysStorage,
         client: RatchetClientProtocol) {
        self.identityPrivateKey = identityPrivateKey
        self.identityCardId = identityCardId
        self.orphanedOneTimeKeyTtl = orphanedOneTimeKeyTtl
        self.longTermKeyTtl = longTermKeyTtl
        self.outdatedLongTermKeyTtl = outdatedLongTermKeyTtl
        self.desiredNumberOfOneTimeKeys = desiredNumberOfOneTimeKeys
        self.longTermKeysStorage = longTermKeysStorage
        self.oneTimeKeysStorage = oneTimeKeysStorage
        self.client = client
    }

    func rotateKeysOperation() -> GenericOperation<Void> {
        return CallbackOperation { operation, completion in
            guard self.mutex.trylock() else {
                Log.debug("Interrupted concurrent keys' rotation")

                completion(nil, NSError())
                return
            }

            Log.debug("Started keys' rotation")

            let completionWrapper: (Void?, Error?) -> Void = {
                self.mutex.unlock()
                self.oneTimeKeysStorage.stopInteraction()
                Log.debug("Completed keys' rotation")

                completion($0, $1)
            }

            do {
                let token: AccessToken = try operation.findDependencyResult()

                let now = Date()

                // TODO: Parallelize
                self.oneTimeKeysStorage.startInteraction()
                let oneTimeKeys = try self.oneTimeKeysStorage.retrieveAllKeys()
                var oneTimeKeysIds = [Data]()
                oneTimeKeysIds.reserveCapacity(oneTimeKeys.count)
                for oneTimeKey in oneTimeKeys {
                    if let orphanedFrom = oneTimeKey.orphanedFrom {
                        if orphanedFrom + self.orphanedOneTimeKeyTtl < now {
                            Log.debug("Removing orphaned one-time key \(oneTimeKey.identifier.hexEncodedString())")
                            try self.oneTimeKeysStorage.deleteKey(withId: oneTimeKey.identifier)
                        }
                    }
                    else {
                        oneTimeKeysIds.append(oneTimeKey.identifier)
                    }
                }

                let longTermKeys = try self.longTermKeysStorage.retrieveAllKeys()
                var lastLongTermKey: LongTermKey? = nil
                for longTermKey in longTermKeys {
                    if let oudatedFrom = longTermKey.outdatedFrom {
                        if oudatedFrom + self.outdatedLongTermKeyTtl < now {
                            Log.debug("Removing outdated long-term key \(longTermKey.identifier.hexEncodedString())")
                            try self.longTermKeysStorage.deleteKey(withId: longTermKey.identifier)
                        }
                    }
                    else {
                        if longTermKey.creationDate + self.longTermKeyTtl < now {
                            Log.debug("Marking long-term key as outdated \(longTermKey.identifier.hexEncodedString())")
                            try self.longTermKeysStorage.markKeyOutdated(startingFrom: now, keyId: longTermKey.identifier)
                        }
                        else {
                            if let key = lastLongTermKey, key.creationDate < longTermKey.creationDate {
                                lastLongTermKey = longTermKey
                            }
                            if lastLongTermKey == nil {
                                lastLongTermKey = longTermKey
                            }
                        }
                    }
                }

                Log.debug("Validating local keys")
                let validateResponse = try self.client.validatePublicKeys(longTermKeyId: lastLongTermKey?.identifier, oneTimeKeysIds: oneTimeKeysIds, token: token.stringRepresentation())

                for usedOneTimeKeyId in validateResponse.usedOneTimeKeysIds {
                    Log.debug("Marking one-time key as orhpaned \(usedOneTimeKeyId.hexEncodedString())")
                    try self.oneTimeKeysStorage.markKeyOrphaned(startingFrom: now, keyId: usedOneTimeKeyId)
                }

                var rotateLongTermKey = false
                if validateResponse.usedLongTermKeyId != nil || lastLongTermKey == nil {
                    rotateLongTermKey = true
                }
                if let lastLongTermKey = lastLongTermKey, lastLongTermKey.creationDate + self.longTermKeyTtl < now {
                    rotateLongTermKey = true
                }

                let longTermSignedPublicKey: SignedPublicKey?
                if rotateLongTermKey {
                    Log.debug("Rotating long-term key")
                    let longTermKeyPair = try self.crypto.generateKeyPair()
                    let longTermPrivateKey = CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(longTermKeyPair.privateKey))
                    let longTermPublicKey = CUtils.extractRawPublicKey(self.crypto.exportPublicKey(longTermKeyPair.publicKey))
                    _ = try self.longTermKeysStorage.storeKey(longTermPrivateKey, withId: SecureChat.computeKeyId(publicKey: longTermPublicKey))
                    longTermSignedPublicKey = SignedPublicKey(publicKey: longTermPublicKey, signature: try self.crypto.generateSignature(of: longTermPublicKey, using: self.identityPrivateKey))
                }
                else {
                    longTermSignedPublicKey = nil
                }

                let numberOfOneTimeKeysToGenerate = max(self.desiredNumberOfOneTimeKeys - (oneTimeKeysIds.count - validateResponse.usedOneTimeKeysIds.count), 0)

                Log.debug("Generating \(numberOfOneTimeKeysToGenerate) one-time keys")
                let oneTimePublicKeys: [Data]
                if numberOfOneTimeKeysToGenerate > 0 {
                    let keyPairs = try self.crypto.generateMultipleKeyPairs(numberOfKeyPairs: UInt(numberOfOneTimeKeysToGenerate))

                    var publicKeys = [Data]()
                    publicKeys.reserveCapacity(numberOfOneTimeKeysToGenerate)
                    for keyPair in keyPairs {
                        let oneTimePrivateKey = CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(keyPair.privateKey))
                        let oneTimePublicKey = CUtils.extractRawPublicKey(self.crypto.exportPublicKey(keyPair.publicKey))
                        let keyId = SecureChat.computeKeyId(publicKey: oneTimePublicKey)
                        _ = try self.oneTimeKeysStorage.storeKey(oneTimePrivateKey, withId: keyId)

                        publicKeys.append(oneTimePublicKey)
                    }

                    oneTimePublicKeys = publicKeys
                }
                else {
                    oneTimePublicKeys = []
                }

                Log.debug("Uploading keys")
                try self.client.uploadPublicKeys(identityCardId: self.identityCardId, longTermPublicKey: longTermSignedPublicKey, oneTimePublicKeys: oneTimePublicKeys, token: token.stringRepresentation())

                completionWrapper(Void(), nil)
            }
            catch {
                completionWrapper(nil, error)
            }
        }
    }
}

extension KeysRotator: KeysRotatorProtocol { }
