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
import VirgilSDK
import VirgilCryptoRatchet
import VirgilCryptoFoundation
import VirgilCryptoApiImpl

@objc(VSRSecureChat) open class SecureChat: NSObject {
    @objc public let accessTokenProvider: AccessTokenProvider
    @objc public let identityPrivateKey: VirgilPrivateKey
    private let keyUtils = RatchetKeyUtils()
    public let client: RatchetClientProtocol
    @objc public let crypto = VirgilCrypto()
    @objc public let longTermKeysStorage: LongTermKeysStorage
    @objc public let oneTimeKeysStorage: OneTimeKeysStorage
    @objc public let sessionStorage: SessionStorage
    private let keysRotator: KeysRotatorProtocol
    
    @objc public convenience init(identity: String, identityCardId: String, identityPrivateKey: VirgilPrivateKey, accessTokenProvider: AccessTokenProvider) throws {
        let client = RatchetClient()
        let longTermKeysStorage = try KeychainLongTermKeysStorage(identity: identity)
        let oneTimeKeysStorage = FileOneTimeKeysStorage(identity: identity)
        let sessionStorage = FileSessionStorage(identity: identity)
        let keysRotator = KeysRotator(identityPrivateKey: identityPrivateKey, identityCardId: identityCardId, longTermKeysStorage: longTermKeysStorage, oneTimeKeysStorage: oneTimeKeysStorage, client: client)
        
        self.init(identityPrivateKey: identityPrivateKey, accessTokenProvider: accessTokenProvider, client: client, longTermKeysStorage: longTermKeysStorage, oneTimeKeysStorage: oneTimeKeysStorage, sessionStorage: sessionStorage, keysRotator: keysRotator)
    }

    public init(identityPrivateKey: VirgilPrivateKey,
                  accessTokenProvider: AccessTokenProvider,
                  client: RatchetClientProtocol,
                  longTermKeysStorage: LongTermKeysStorage,
                  oneTimeKeysStorage: OneTimeKeysStorage,
                  sessionStorage: SessionStorage,
                  keysRotator: KeysRotatorProtocol) {
        self.identityPrivateKey = identityPrivateKey
        self.accessTokenProvider = accessTokenProvider
        self.client = client
        self.longTermKeysStorage = longTermKeysStorage
        self.oneTimeKeysStorage = oneTimeKeysStorage
        self.sessionStorage = sessionStorage
        self.keysRotator = keysRotator

        super.init()
    }

    @objc public func rotateKeys(completion: @escaping (Error?) -> Void) {
        self.rotateKeys().start(completion: {
            completion($1)
        })
    }

    public func rotateKeys() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            let tokenContext = TokenContext(service: "ratchet", operation: "rotate", forceReload: false)
            let getTokenOperation = OperationUtils.makeGetTokenOperation(
                tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
            let rotateKeysOperation = self.keysRotator.rotateKeysOperation()

            let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

            rotateKeysOperation.addDependency(getTokenOperation)

            completionOperation.addDependency(getTokenOperation)
            completionOperation.addDependency(rotateKeysOperation)

            let queue = OperationQueue()
            let operations = [getTokenOperation, rotateKeysOperation, completionOperation]
            queue.addOperations(operations, waitUntilFinished: false)
        }
    }

    @objc open func existingSession(withParticpantIdentity particpantIdentity: String) -> SecureSession? {
        return self.sessionStorage.retrieveSession(participantIdentity: particpantIdentity)
    }

    @objc func deleteSession(withParticpantIdentity particpantIdentity: String) throws {
        // FIXME
        throw NSError()
    }

    @objc open func startNewSessionAsSender(receiverCard: Card) throws -> SecureSession {
        let tokenContext = TokenContext(service: "ratchet", operation: "get")
        let getTokenOperation = OperationUtils.makeGetTokenOperation(
            tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

        // FIXME: run async
        let token = try getTokenOperation.startSync().getResult()

        guard self.existingSession(withParticpantIdentity: receiverCard.identity) == nil else {
            throw NSError()
        }

        // FIXME: run async
        let publicKeySet = try self.client.getPublicKeySet(forRecipientIdentity: receiverCard.identity, token: token.stringRepresentation())

        guard let identityPublicKey = receiverCard.publicKey as? VirgilPublicKey else {
            throw NSError()
        }

        guard self.crypto.exportPublicKey(identityPublicKey) == publicKeySet.identityPublicKey else {
            throw NSError()
        }

        // FIXME
        guard self.crypto.verifySignature(publicKeySet.longTermPublicKey.signature, of: publicKeySet.longTermPublicKey.publicKey, with: identityPublicKey) else {
            throw NSError()
        }

        if publicKeySet.oneTimePublicKey == nil {
            Log.error("Creating weak session with \(receiverCard.identity)")
        }

        let privateKeyData = self.crypto.exportPrivateKey(self.identityPrivateKey)

        let session = try SecureSession(sessionStorage: self.sessionStorage,
                                        participantIdentity: receiverCard.identity,
                                        senderIdentityPrivateKey: privateKeyData,
                                        receiverIdentityPublicKey: publicKeySet.identityPublicKey,
                                        receiverLongTermPublicKey: publicKeySet.longTermPublicKey.publicKey,
                                        receiverOneTimePublicKey: publicKeySet.oneTimePublicKey)

        try self.sessionStorage.storeSession(session)

        return session
    }

    private let queue = DispatchQueue(label: "VSRSecureChat", qos: .background)
    private func replaceOneTimeKey() {
        Log.debug("Adding one time key queued")

        self.queue.async {
            Log.debug("Adding one time started")

            let oneTimePublicKey: Data

            do {
                try self.oneTimeKeysStorage.startInteraction()

                defer {
                    try? self.oneTimeKeysStorage.stopInteraction()
                }

                let keyPair = try self.crypto.generateKeyPair(ofType: .FAST_EC_X25519)

                let oneTimePrivateKey = self.crypto.exportPrivateKey(keyPair.privateKey)
                oneTimePublicKey = self.crypto.exportPublicKey(keyPair.publicKey)
                let keyId = try self.keyUtils.computePublicKeyId(publicKey: oneTimePublicKey)

                _ = try self.oneTimeKeysStorage.storeKey(oneTimePrivateKey, withId: keyId)

                Log.debug("Saved one-time key successfully")
            }
            catch {
                Log.error("Error saving one-time key")
                return
            }

            do {
                let token = try OperationUtils.makeGetTokenOperation(tokenContext: TokenContext(service: "ratchet", operation: "post"), accessTokenProvider: self.accessTokenProvider).startSync().getResult()

                try self.client.uploadPublicKeys(identityCardId: nil, longTermPublicKey: nil, oneTimePublicKeys: [oneTimePublicKey], token: token.stringRepresentation())

                Log.debug("Added one-time key successfully")
            }
            catch {
                Log.error("Error adding one-time key")
            }
        }
    }

    @objc public func startNewSessionAsReceiver(senderCard: Card, ratchetMessage: RatchetMessage) throws -> SecureSession {
        guard let senderIdentityPublicKey = senderCard.publicKey as? VirgilPublicKey else {
            throw NSError()
        }

        guard ratchetMessage.getType() == .prekey else {
            throw NSError()
        }

        let receiverLongTermPublicKey = ratchetMessage.getLongTermPublicKey()
        let receiverLongTermPrivateKey = try self.longTermKeysStorage.retrieveKey(withId: try self.keyUtils.computePublicKeyId(publicKey: receiverLongTermPublicKey))

        let receiverOneTimePublicKey = ratchetMessage.getOneTimePublicKey()
        let receiverOneTimeKeyId: Data? = receiverOneTimePublicKey.isEmpty ? nil : try self.keyUtils.computePublicKeyId(publicKey: receiverOneTimePublicKey)

        let receiverOneTimePrivateKey: OneTimeKey?

        if let receiverOneTimeKeyId = receiverOneTimeKeyId {
            try self.oneTimeKeysStorage.startInteraction()

            receiverOneTimePrivateKey = try self.oneTimeKeysStorage.retrieveKey(withId: receiverOneTimeKeyId)
        }
        else {
            receiverOneTimePrivateKey = nil
        }

        let session: SecureSession

        do {
            session = try SecureSession(sessionStorage: self.sessionStorage,
                                        participantIdentity: senderCard.identity,
                                        receiverIdentityPrivateKey: self.identityPrivateKey,
                                        receiverLongTermPrivateKey: receiverLongTermPrivateKey,
                                        receiverOneTimePrivateKey: receiverOneTimePrivateKey,
                                        senderIdentityPublicKey: self.crypto.exportPublicKey(senderIdentityPublicKey),
                                        ratchetMessage: ratchetMessage)
        }
        catch {
            try self.oneTimeKeysStorage.stopInteraction()

            throw error
        }

        if let receiverOneTimeKeyId = receiverOneTimeKeyId {
            defer {
                try? self.oneTimeKeysStorage.stopInteraction()
            }

            try self.oneTimeKeysStorage.deleteKey(withId: receiverOneTimeKeyId)

            self.replaceOneTimeKey()
        }

        try self.sessionStorage.storeSession(session)

        return session
    }
}
