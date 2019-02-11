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
import VirgilCryptoRatchet

/// KeysRotator errors
///
/// - concurrentRotation: concurrent rotation is not allowed
public enum KeysRotatorError: Int, Error {
    case concurrentRotation = 1
}

/// Default implementation of KeysRotatorProtocol
public class KeysRotator {
    private let crypto = VirgilCrypto(defaultKeyType: .FAST_EC_X25519, useSHA256Fingerprints: false)
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
    private let keyUtils = RatchetKeyUtils()

    /// Initializer
    ///
    /// - Parameters:
    ///   - identityPrivateKey: identity private key
    ///   - identityCardId: identity card id
    ///   - orphanedOneTimeKeyTtl: time that one-time key lives in the storage after been marked as orphaned. Seconds
    ///   - longTermKeyTtl: time that long-term key is been used before rotation. Seconds
    ///   - outdatedLongTermKeyTtl: time that long-term key lives in the storage after been marked as outdated. Seconds
    ///   - desiredNumberOfOneTimeKeys: desired number of one-time keys
    ///   - longTermKeysStorage: long-term keys storage
    ///   - oneTimeKeysStorage: one-time keys storage
    ///   - client: RatchetClient
    public init(identityPrivateKey: VirgilPrivateKey,
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

    /// Rotates keys
    ///
    /// Rotation process:
    ///         - Retrieve all one-time keys
    ///         - Delete one-time keys that were marked as orphaned more than orphanedOneTimeKeyTtl seconds ago
    ///         - Retrieve all long-term keys
    ///         - Delete long-term keys that were marked as outdated more than outdatedLongTermKeyTtl seconds ago
    ///         - Check that all relevant long-term and one-time keys are in the cloud
    ///             (still persistent in the cloud and were not used)
    ///         - Mark used one-time keys as used
    ///         - Decide on long-term key roration
    ///         - Generate needed number of one-time keys
    ///         - Upload keys to the cloud
    ///
    /// - Returns: GenericOperation
    public func rotateKeysOperation() -> GenericOperation<Void> {
        return CallbackOperation { operation, completion in
            guard self.mutex.trylock() else {
                Log.debug("Interrupted concurrent keys' rotation")

                completion(nil, KeysRotatorError.concurrentRotation)
                return
            }

            Log.debug("Started keys' rotation")

            let completionWrapper: (Void?, Error?) -> Void = {
                do {
                    try self.mutex.unlock()
                }
                catch {
                    completion(nil, error)
                    return
                }

                do {
                    try self.oneTimeKeysStorage.stopInteraction()
                }
                catch {
                    Log.debug("Completed keys' rotation with error")
                    completion(nil, error)
                    return
                }

                if let error = $1 {
                    Log.debug("Completed keys' rotation with error")
                    completion(nil, error)
                    return
                }
                else if let res = $0 {
                    Log.debug("Completed keys' rotation successfully")
                    completion(res, nil)
                    return
                }

                completion(nil, nil)
            }

            do {
                let token: AccessToken = try operation.findDependencyResult()

                let now = Date()

                try self.oneTimeKeysStorage.startInteraction()
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
                            try self.longTermKeysStorage.markKeyOutdated(startingFrom: now,
                                                                         keyId: longTermKey.identifier)
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
                let validateResponse = try self.client.validatePublicKeys(longTermKeyId: lastLongTermKey?.identifier,
                                                                          oneTimeKeysIds: oneTimeKeysIds,
                                                                          token: token.stringRepresentation())

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
                    let longTermPrivateKey = self.crypto.exportPrivateKey(longTermKeyPair.privateKey)
                    let longTermPublicKey = self.crypto.exportPublicKey(longTermKeyPair.publicKey)
                    let longTermKeyId = try self.keyUtils.computePublicKeyId(publicKey: longTermPublicKey)
                    _ = try self.longTermKeysStorage.storeKey(longTermPrivateKey,
                                                              withId: longTermKeyId)
                    let longTermKeySignature = try self.crypto.generateSignature(of: longTermPublicKey,
                                                                                 using: self.identityPrivateKey)
                    longTermSignedPublicKey = SignedPublicKey(publicKey: longTermPublicKey,
                                                              signature: longTermKeySignature)
                }
                else {
                    longTermSignedPublicKey = nil
                }

                let numOfrelevantOneTimeKeys = oneTimeKeysIds.count - validateResponse.usedOneTimeKeysIds.count
                let numbOfOneTimeKeysToGen = UInt(max(self.desiredNumberOfOneTimeKeys - numOfrelevantOneTimeKeys, 0))

                Log.debug("Generating \(numbOfOneTimeKeysToGen) one-time keys")
                let oneTimePublicKeys: [Data]
                if numbOfOneTimeKeysToGen > 0 {
                    let keyPairs = try self.crypto.generateMultipleKeyPairs(numberOfKeyPairs: numbOfOneTimeKeysToGen)

                    var publicKeys = [Data]()
                    publicKeys.reserveCapacity(Int(numbOfOneTimeKeysToGen))
                    for keyPair in keyPairs {
                        let oneTimePrivateKey = self.crypto.exportPrivateKey(keyPair.privateKey)
                        let oneTimePublicKey = self.crypto.exportPublicKey(keyPair.publicKey)
                        let keyId = try self.keyUtils.computePublicKeyId(publicKey: oneTimePublicKey)
                        _ = try self.oneTimeKeysStorage.storeKey(oneTimePrivateKey, withId: keyId)

                        publicKeys.append(oneTimePublicKey)
                    }

                    oneTimePublicKeys = publicKeys
                }
                else {
                    oneTimePublicKeys = []
                }

                Log.debug("Uploading keys")
                try self.client.uploadPublicKeys(identityCardId: self.identityCardId,
                                                 longTermPublicKey: longTermSignedPublicKey,
                                                 oneTimePublicKeys: oneTimePublicKeys,
                                                 token: token.stringRepresentation())

                completionWrapper(Void(), nil)
            }
            catch {
                completionWrapper(nil, error)
            }
        }
    }
}

// MARK: - KeysRotatorProtocol
extension KeysRotator: KeysRotatorProtocol { }
