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

import XCTest
import VirgilSDK
import VirgilCrypto
import VSCRatchet
@testable import VirgilSDKRatchet

class SecureSessionTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func initChat() throws -> (Card, Card, SecureChat, SecureChat) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        let receiverIdentityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        let senderIdentityKeyPair = try! crypto.generateKeyPair(ofType: .ed25519)
        
        let senderIdentity = NSUUID().uuidString
        let receiverIdentity = NSUUID().uuidString
        
        let receiverTokenProvider = CallbackJwtProvider(getJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
            
            let generator = try! JwtGenerator(apiKey: privateKey,
                                              apiPublicKeyIdentifier: testConfig.ApiKeyId,
                                              crypto: crypto,
                                              appId: testConfig.AppId,
                                              ttl: 10050)
            
            completion(try! generator.generateToken(identity: receiverIdentity), nil)
        })
        
        let senderTokenProvider = CallbackJwtProvider(getJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
            
            let generator = try! JwtGenerator(apiKey: privateKey,
                                              apiPublicKeyIdentifier: testConfig.ApiKeyId,
                                              crypto: crypto,
                                              appId: testConfig.AppId,
                                              ttl: 10050)
            
            completion(try! generator.generateToken(identity: senderIdentity), nil)
        })
        
        let cardVerifier = PositiveCardVerifier()
        let ramCardClient = RamCardClient()
        
        let senderCardManagerParams = CardManagerParams(crypto: crypto, accessTokenProvider: senderTokenProvider, cardVerifier: cardVerifier)
        senderCardManagerParams.cardClient = ramCardClient
        
        let senderCardManager = CardManager(params: senderCardManagerParams)
        
        let receiverCardManagerParams = CardManagerParams(crypto: crypto, accessTokenProvider: receiverTokenProvider, cardVerifier: cardVerifier)
        receiverCardManagerParams.cardClient = ramCardClient
        
        let receiverCardManager = CardManager(params: receiverCardManagerParams)
        
        let receiverCard = try receiverCardManager.publishCard(privateKey: receiverIdentityKeyPair.privateKey, publicKey: receiverIdentityKeyPair.publicKey, identity: receiverIdentity).startSync().get()
        let senderCard = try senderCardManager.publishCard(privateKey: senderIdentityKeyPair.privateKey, publicKey: senderIdentityKeyPair.publicKey, identity: senderIdentity).startSync().get()
        
        let receiverLongTermKeysStorage = RamLongTermKeysStorage(db: [:])
        let receiverOneTimeKeysStorage = RamOneTimeKeysStorage(db: [:])
        
        let storage = RamClient.Storage()
        
        let senderFakeClient = RamClient(identity: senderIdentity, storage: storage, cardManager: senderCardManager)
        let receiverFakeClient = RamClient(identity: receiverIdentity, storage: storage, cardManager: receiverCardManager)
        
        let senderSecureChat = SecureChat(crypto: crypto,
                                          identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          identityCard: senderCard,
                                          client: senderFakeClient,
                                          longTermKeysStorage: RamLongTermKeysStorage(db: [:]),
                                          oneTimeKeysStorage: RamOneTimeKeysStorage(db: [:]),
                                          sessionStorage: RamSessionStorage(),
                                          groupSessionStorage:  RamGroupSessionStorage(),
                                          keysRotator: FakeKeysRotator())
        
        let receiverKeysRotator = KeysRotator(crypto: crypto, identityPrivateKey: receiverIdentityKeyPair.privateKey, identityCardId: receiverCard.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: 10, longTermKeysStorage: receiverLongTermKeysStorage, oneTimeKeysStorage: receiverOneTimeKeysStorage, client: receiverFakeClient)
        
        let receiverSecureChat = SecureChat(crypto: crypto,
                                            identityPrivateKey: receiverIdentityKeyPair.privateKey,
                                            identityCard: receiverCard,
                                            client: receiverFakeClient,
                                            longTermKeysStorage: receiverLongTermKeysStorage,
                                            oneTimeKeysStorage: receiverOneTimeKeysStorage,
                                            sessionStorage: RamSessionStorage(),
                                            groupSessionStorage:  RamGroupSessionStorage(),
                                            keysRotator: receiverKeysRotator)
    
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }

    func test1__encrypt_decrypt__random_uuid_messages_ram_client__should_decrypt() {
        do {
            let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            
            let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().get()
            
            let plainText = UUID().uuidString
            let cipherText = try senderSession.encrypt(string: plainText)
            
            let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
            
            let decryptedMessage = try receiverSession.decryptString(from: cipherText)
            
            XCTAssert(decryptedMessage == plainText)
            
            try Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test2__session_persistence__random_uuid_messages_ram_client__should_decrypt() {
        do {
            let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            
            let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().get()
            
            try senderSecureChat.storeSession(senderSession)
            
            XCTAssert(senderSecureChat.existingSession(withParticipantIdentity: receiverCard.identity) != nil)
            
            let plainText = UUID().uuidString
            let cipherText = try senderSession.encrypt(string: plainText)
            
            let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
            
            try receiverSecureChat.storeSession(receiverSession)
            
            XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) != nil)
            
            let decryptedMessage = try receiverSession.decryptString(from: cipherText)
            
            XCTAssert(decryptedMessage == plainText)
            
            try Utils.encryptDecrypt100TimesRestored(senderSecureChat: senderSecureChat, senderIdentity: senderCard.identity, receiverSecureChat: receiverSecureChat, receiverIdentity: receiverCard.identity)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test3__session_persistence__recreate_session__should_throw_error() {
        do {
            let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            
            let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().get()
            
            try senderSecureChat.storeSession(senderSession)
            
            let plainText = UUID().uuidString
            let cipherText = try senderSession.encrypt(string: plainText)
            
            let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
            
            try receiverSecureChat.storeSession(receiverSession)
            
            do {
                _ = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard).startSync().get()
                XCTFail()
            }
            catch SecureChatError.sessionAlreadyExists { }
            catch {
                XCTFail()
            }
            
            do {
                _ = try senderSecureChat.startNewSessionAsReceiver(senderCard: receiverCard, ratchetMessage: cipherText)
                XCTFail()
            }
            catch SecureChatError.sessionAlreadyExists { }
            catch {
                XCTFail()
            }
            
            do {
                _ = try receiverSecureChat.startNewSessionAsSender(receiverCard: senderCard).startSync().get()
                XCTFail()
            }
            catch SecureChatError.sessionAlreadyExists { }
            catch {
                XCTFail()
            }
            
            do {
                _ = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText)
                XCTFail()
            }
            catch SecureChatError.sessionAlreadyExists { }
            catch {
                XCTFail()
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
}
