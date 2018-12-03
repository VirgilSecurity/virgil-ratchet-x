//
// Copyright (C) 2015-2018 Virgil Security Inc.
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
import VSCRatchet
import VirgilCryptoApiImpl

@objc(VSRSecureChat) open class SecureChat: NSObject {
    @objc public let accessTokenProvider: AccessTokenProvider
    @objc public let identityPrivateKey: VirgilPrivateKey
    public let client: RatchetClientProtocol
    @objc public let crypto = VirgilCrypto(defaultKeyType: .EC_CURVE25519, useSHA256Fingerprints: false)
    @objc public let longTermKeysStorage: LongTermKeysStorage
    @objc public let oneTimeKeysStorage: OneTimeKeysStorage
    @objc public let sessionStorage: SessionStorage
    private let keysRotator: KeysRotatorProtocol

    // FIXME
    internal init(identityPrivateKey: VirgilPrivateKey,
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
        
        let privateKeyData = CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(self.identityPrivateKey))
        
        let session = try SecureSession(sessionStorage: self.sessionStorage,
                                        participantIdentity: receiverCard.identity,
                                        senderIdentityPrivateKey: privateKeyData,
                                        receiverIdentityPublicKey: CUtils.extractRawPublicKey(publicKeySet.identityPublicKey),
                                        receiverLongTermPublicKey: publicKeySet.longTermPublicKey.publicKey,
                                        receiverOneTimePublicKey: publicKeySet.oneTimePublicKey)
        
        try self.sessionStorage.storeSession(session)
        
        return session
    }
    
    private let queue = DispatchQueue(label: "VSRSecureChat", qos: .background)
    private func replaceOneTimeKey(withId receiverOneTimeKeyId: Data) {
        Log.debug("Adding one time key")

        self.queue.async {
            do {
                let keyPair = try self.crypto.generateKeyPair()
                
                let oneTimePrivateKey = CUtils.extractRawPrivateKey(self.crypto.exportPrivateKey(keyPair.privateKey))
                let oneTimePublicKey = CUtils.extractRawPublicKey(self.crypto.exportPublicKey(keyPair.publicKey))
                let keyId = CUtils.computeKeyId(publicKey: oneTimePublicKey)
                
                try self.oneTimeKeysStorage.deleteKey(withId: receiverOneTimeKeyId)
                _ = try self.oneTimeKeysStorage.storeKey(oneTimePrivateKey, withId: keyId)
                
                let token = try OperationUtils.makeGetTokenOperation(tokenContext: TokenContext(service: "ratchet", operation: "post"), accessTokenProvider: self.accessTokenProvider).startSync().getResult()
                
                try self.client.uploadPublicKeys(identityCardId: nil, longTermPublicKey: nil, oneTimePublicKeys: [oneTimePublicKey], token: token.stringRepresentation())
                
                try self.client.uploadPublicKeys(identityCardId: nil, longTermPublicKey: nil, oneTimePublicKeys: [oneTimePublicKey], token: token.stringRepresentation())
                
                Log.debug("Added one-time key successfully")
            }
            catch {
                Log.error("Error adding one-time key")
            }
        }
    }
    
    @objc public func startNewSessionAsReceiver(senderCard: Card, ratchetMessage: UnsafePointer<vscr_ratchet_message_t>) throws -> SecureSession {
        guard let senderIdentityPublicKey = senderCard.publicKey as? VirgilPublicKey else {
            throw NSError()
        }
        
        guard ratchetMessage.pointee.type == vscr_ratchet_message_TYPE_PREKEY else {
            throw NSError()
        }
        
        // FIXME
        guard let prekeyMessage = vscr_ratchet_prekey_message_deserialize(vsc_buffer_data(ratchetMessage.pointee.message), nil) else {
            throw NSError()
        }
        
        // FIXME
        guard let regularMessage = vscr_ratchet_regular_message_deserialize(vsc_buffer_data(prekeyMessage.pointee.message), nil) else {
            throw NSError()
        }
        
        let receiverLongTermPublicKey = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: vsc_buffer_bytes(prekeyMessage.pointee.receiver_long_term_key)!), count: vsc_buffer_len(prekeyMessage.pointee.receiver_long_term_key), deallocator: Data.Deallocator.none)
        
        // CHECK one time is zero
        let receiverOneTimePublicKey = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: vsc_buffer_bytes(prekeyMessage.pointee.receiver_one_time_key)!), count: vsc_buffer_len(prekeyMessage.pointee.receiver_one_time_key), deallocator: Data.Deallocator.none)
        
        let receiverLongTermPrivateKey = try self.longTermKeysStorage.retrieveKey(withId: CUtils.computeKeyId(publicKey: receiverLongTermPublicKey))
        let receiverOneTimeKeyId = CUtils.computeKeyId(publicKey: receiverOneTimePublicKey)
        
        self.oneTimeKeysStorage.startInteraction()
        let receiverOneTimePrivateKey = try self.oneTimeKeysStorage.retrieveKey(withId: receiverOneTimeKeyId)
        
        let session = try SecureSession(sessionStorage: self.sessionStorage,
                                        participantIdentity: senderCard.identity,
                                        receiverIdentityPrivateKey: self.identityPrivateKey,
                                        receiverLongTermPrivateKey: receiverLongTermPrivateKey,
                                        receiverOneTimePrivateKey: receiverOneTimePrivateKey,
                                        senderIdentityPublicKey: CUtils.extractRawPublicKey(self.crypto.exportPublicKey(senderIdentityPublicKey)),
                                        senderEphemeralPublicKey: prekeyMessage.pointee.sender_ephemeral_key,
                                        ratchetPublicKey: regularMessage.pointee.public_key,
                                        regularMessage: regularMessage)

        self.replaceOneTimeKey(withId: receiverOneTimeKeyId)
        
        defer {
            self.oneTimeKeysStorage.stopInteraction()
            vscr_ratchet_regular_message_delete(regularMessage)
            vscr_ratchet_prekey_message_delete(prekeyMessage)
        }
        
        try self.sessionStorage.storeSession(session)
        
        return session
    }
}
