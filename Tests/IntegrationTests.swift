//
// Copyright (C) 2015-2020 Virgil Security Inc.
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

class IntegrationTests: XCTestCase {
    
    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    static let desiredNumberOfOtKeys = 5
    
    private func initChat() throws -> (Card, Card, SecureChat, SecureChat) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = try! VirgilCrypto()
        let receiverIdentityKeyPair = try! crypto.generateKeyPair(ofType: .curve25519Round5Ed25519Falcon)
        let senderIdentityKeyPair = try! crypto.generateKeyPair(ofType: .curve25519Round5Ed25519Falcon)
        
        let senderIdentity = NSUUID().uuidString
        let receiverIdentity = NSUUID().uuidString
        
        let receiverTokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
            
            let generator = try! JwtGenerator(apiKey: privateKey,
                                              apiPublicKeyIdentifier: testConfig.ApiKeyId,
                                              crypto: crypto,
                                              appId: testConfig.AppId,
                                              ttl: 10050)
            
            completion(try! generator.generateToken(identity: receiverIdentity), nil)
        })
        
        let senderTokenProvider = CachingJwtProvider(renewJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!).privateKey
            
            let generator = try! JwtGenerator(apiKey: privateKey,
                                              apiPublicKeyIdentifier: testConfig.ApiKeyId,
                                              crypto: crypto,
                                              appId: testConfig.AppId,
                                              ttl: 10050)
            
            completion(try! generator.generateToken(identity: senderIdentity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(crypto: crypto)!
        cardVerifier.verifyVirgilSignature = false
        
        let senderCardManagerParams = CardManagerParams(crypto: crypto, accessTokenProvider: senderTokenProvider, cardVerifier: cardVerifier)
        let receiverCardManagerParams = CardManagerParams(crypto: crypto, accessTokenProvider: receiverTokenProvider, cardVerifier: cardVerifier)
        senderCardManagerParams.cardClient = CardClient(accessTokenProvider: senderTokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
        receiverCardManagerParams.cardClient = CardClient(accessTokenProvider: receiverTokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let senderCardManager = CardManager(params: senderCardManagerParams)
        let receiverCardManager = CardManager(params: receiverCardManagerParams)
        
        let receiverCard = try receiverCardManager.publishCard(privateKey: receiverIdentityKeyPair.privateKey, publicKey: receiverIdentityKeyPair.publicKey, identity: receiverIdentity).startSync().get()
        let senderCard = try senderCardManager.publishCard(privateKey: senderIdentityKeyPair.privateKey, publicKey: senderIdentityKeyPair.publicKey, identity: senderIdentity).startSync().get()
        
        let params = try KeychainStorageParams.makeKeychainStorageParams(appName: "test")
        let receiverLongTermKeysStorage = try KeychainLongTermKeysStorage(identity: receiverIdentity, params: params)
        let senderLongTermKeysStorage = try KeychainLongTermKeysStorage(identity: senderIdentity, params: params)
        
        let receiverOneTimeKeysStorage = try SQLiteOneTimeKeysStorage(appGroup: nil, identity: receiverIdentity, crypto: crypto, identityKeyPair: receiverIdentityKeyPair)
        let senderOneTimeKeysStorage = try SQLiteOneTimeKeysStorage(appGroup: nil, identity: senderIdentity, crypto: crypto, identityKeyPair: senderIdentityKeyPair)

        let receiverClient = RatchetClient(accessTokenProvider: receiverTokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
        let senderClient = RatchetClient(accessTokenProvider: senderTokenProvider, serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let receiverKeysRotator = KeysRotator(crypto: crypto, identityPrivateKey: receiverIdentityKeyPair.privateKey, identityCardId: receiverCard.identifier, orphanedOneTimeKeyTtl: 5, longTermKeyTtl: 10, outdatedLongTermKeyTtl: 5, desiredNumberOfOneTimeKeys: IntegrationTests.desiredNumberOfOtKeys, enablePostQuantum: true, longTermKeysStorage: receiverLongTermKeysStorage, oneTimeKeysStorage: receiverOneTimeKeysStorage, client: receiverClient)
        
        let senderKeysRotator = KeysRotator(crypto: crypto, identityPrivateKey: senderIdentityKeyPair.privateKey, identityCardId: senderCard.identifier, orphanedOneTimeKeyTtl: 100, longTermKeyTtl: 100, outdatedLongTermKeyTtl: 100, desiredNumberOfOneTimeKeys: IntegrationTests.desiredNumberOfOtKeys, enablePostQuantum: true, longTermKeysStorage: senderLongTermKeysStorage, oneTimeKeysStorage: senderOneTimeKeysStorage, client: senderClient)
        
        let senderSecureChat = SecureChat(crypto: crypto,
                                          identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          identityCard: senderCard,
                                          client: senderClient,
                                          longTermKeysStorage: senderLongTermKeysStorage,
                                          oneTimeKeysStorage: senderOneTimeKeysStorage,
                                          sessionStorage: FileSessionStorage(appGroup: nil, identity: senderIdentity, crypto: crypto, identityKeyPair: senderIdentityKeyPair),
                                          keysRotator: senderKeysRotator, keyPairType: .curve25519Round5)
        
        let receiverSecureChat = SecureChat(crypto: crypto,
                                            identityPrivateKey: receiverIdentityKeyPair.privateKey,
                                            identityCard: receiverCard,
                                            client: receiverClient,
                                            longTermKeysStorage: receiverLongTermKeysStorage,
                                            oneTimeKeysStorage: receiverOneTimeKeysStorage,
                                            sessionStorage: FileSessionStorage(appGroup: nil, identity: receiverIdentity, crypto: crypto, identityKeyPair: receiverIdentityKeyPair),
                                            keysRotator: receiverKeysRotator, keyPairType: .curve25519Round5)
        
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }
    
    func test1__encrypt_decrypt__random_uuid_messages__should_decrypt() {
        do {
            for i in 0..<2 {
                let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                
                let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard, enablePostQuantum: i == 1).startSync().get()
                
                let plainText = UUID().uuidString
                let cipherText = try senderSession.encrypt(string: plainText)
                
                let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText, enablePostQuantum: i == 1)
                
                let decryptedMessage = try receiverSession.decryptString(from: cipherText)
                
                XCTAssert(decryptedMessage == plainText)
                
                try Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test2__session_persistence__random_uuid_messages__should_decrypt() {
        do {
            for i in 0..<2 {
                let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                
                let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard, enablePostQuantum: i == 1).startSync().get()
                
                try senderSecureChat.storeSession(senderSession)
                
                XCTAssert(senderSecureChat.existingSession(withParticipantIdentity: receiverCard.identity) != nil)
                
                let plainText = UUID().uuidString
                let cipherText = try senderSession.encrypt(string: plainText)
                
                try senderSecureChat.storeSession(senderSession)
                
                let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText, enablePostQuantum: i == 1)
                
                try receiverSecureChat.storeSession(receiverSession)
                
                XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) != nil)
                
                let decryptedMessage = try receiverSession.decryptString(from: cipherText)
                
                try receiverSecureChat.storeSession(receiverSession)
                
                XCTAssert(decryptedMessage == plainText)
                
                try Utils.encryptDecrypt100TimesRestored(senderSecureChat: senderSecureChat, senderIdentity: senderCard.identity, receiverSecureChat: receiverSecureChat, receiverIdentity: receiverCard.identity)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test3__session_removal__one_session_per_participant__should_delete_session() {
        do {
            for i in 0..<2 {
                let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                
                let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard, enablePostQuantum: i == 1).startSync().get()
                
                XCTAssert(senderSecureChat.existingSession(withParticipantIdentity: receiverCard.identity) == nil)
                
                try senderSecureChat.storeSession(senderSession)
                
                XCTAssert(senderSecureChat.existingSession(withParticipantIdentity: receiverCard.identity) != nil)
                
                let plainText = UUID().uuidString
                let cipherText = try senderSession.encrypt(string: plainText)
                
                let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText, enablePostQuantum: i == 1)
                
                XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) == nil)
                
                try receiverSecureChat.storeSession(receiverSession)

                XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) != nil)
                
                let decryptedMessage = try receiverSession.decryptString(from: cipherText)
                
                XCTAssert(decryptedMessage == plainText)
                
                try Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
                
                try senderSecureChat.deleteSession(withParticipantIdentity: receiverCard.identity)
                try receiverSecureChat.deleteSession(withParticipantIdentity: senderCard.identity)
                
                XCTAssert(senderSecureChat.existingSession(withParticipantIdentity: receiverCard.identity) == nil)
                XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) == nil)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test4__reset__one_session_per_participant__should_reset() {
        do {
            for i in 0..<2 {
                let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                _ = try senderSecureChat.rotateKeys().startSync().get()
            
                let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard, enablePostQuantum: i == 1).startSync().get()
                
                try senderSecureChat.storeSession(senderSession)
                
                let plainText = UUID().uuidString
                let cipherText = try senderSession.encrypt(string: plainText)
                
                let receiverSession = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText, enablePostQuantum: i == 1)
                
                try receiverSecureChat.storeSession(receiverSession)
                
                let decryptedMessage = try receiverSession.decryptString(from: cipherText)
                
                XCTAssert(decryptedMessage == plainText)
                
                try Utils.encryptDecrypt100Times(senderSession: senderSession, receiverSession: receiverSession)
                
                sleep(3)
                
                try senderSecureChat.reset().startSync().get()
                
                XCTAssert(senderSecureChat.existingSession(withParticipantIdentity: receiverCard.identity) == nil)
                XCTAssert(try senderSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty)
                
                XCTAssert(try senderSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty)
                
                // Check that reset haven't affecter receivers
                XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) != nil)
                
                sleep(5)
            
                try receiverSecureChat.reset().startSync().get()
                
                XCTAssert(receiverSecureChat.existingSession(withParticipantIdentity: senderCard.identity) == nil)
                XCTAssert(try receiverSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty)
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test5__start_as_receiver__one_session__should_replenish_ot_key() {
        do {
            for i in 0..<2 {
                let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                _ = try senderSecureChat.rotateKeys().startSync().get()
                
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().count == IntegrationTests.desiredNumberOfOtKeys)
                
                let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard, enablePostQuantum: i == 1).startSync().get()
                
                let plainText = UUID().uuidString
                let cipherText = try senderSession.encrypt(string: plainText)
                
                _ = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText, enablePostQuantum: i == 1)
                
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().count == IntegrationTests.desiredNumberOfOtKeys - 1)
                
                sleep(5)
                
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().count == IntegrationTests.desiredNumberOfOtKeys)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test6__rotate__double_rotate_empty_storage__should_complete() {
        do {
            let (_, _, _, receiverSecureChat) = try self.initChat()
        
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            _ = try receiverSecureChat.rotateKeys().startSync().get()
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test7__rotate__one_session__should_replenish_ot_key() {
        do {
            for i in 0..<2 {
                let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = try self.initChat()
            
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                            
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().count == IntegrationTests.desiredNumberOfOtKeys)
                
                let senderSession = try senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard, enablePostQuantum: i == 1).startSync().get()
                
                let plainText = UUID().uuidString
                let cipherText = try senderSession.encrypt(string: plainText)
                
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().count == IntegrationTests.desiredNumberOfOtKeys + 1)
                
                sleep(6)
                
                _ = try receiverSecureChat.rotateKeys().startSync().get()
                
                XCTAssert(try receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().count == IntegrationTests.desiredNumberOfOtKeys)
                            
                do {
                    _ = try receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, ratchetMessage: cipherText, enablePostQuantum: i == 1)
                    XCTAssert(false)
                }
                catch { }
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test8__rotate__ltk_outdated__should_outdate_and_delete_ltk() {
        do {
            let (_, _, _, receiverSecureChat) = try self.initChat()
        
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            
            XCTAssert(try receiverSecureChat.longTermKeysStorage.retrieveAllKeys().count == 1)
            
            sleep(11)
            
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            
            XCTAssert(try receiverSecureChat.longTermKeysStorage.retrieveAllKeys().count == 2)
            
            sleep(5)
            
            _ = try receiverSecureChat.rotateKeys().startSync().get()
            
            XCTAssert(try receiverSecureChat.longTermKeysStorage.retrieveAllKeys().count == 1)
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test9__start_multiple_chats__random_uuid_messages__should_decrypt() {
        do {
            for i in 0..<2 {
                let (card1, card2, chat1, chat2) = try self.initChat()
                let (card3, card4, chat3, chat4) = try self.initChat()
                
                _ = try chat2.rotateKeys().startSync().get()
                _ = try chat3.rotateKeys().startSync().get()
                _ = try chat4.rotateKeys().startSync().get()
                
                let sessions = try chat1.startMutipleNewSessionsAsSender(receiverCards: [card2, card3, card4], enablePostQuantum: i == 1).startSync().get()
                
                let plainText2 = UUID().uuidString
                let plainText3 = UUID().uuidString
                let plainText4 = UUID().uuidString
            
                let cipherText2 = try sessions[0].encrypt(string: plainText2)
                let cipherText3 = try sessions[1].encrypt(string: plainText3)
                let cipherText4 = try sessions[2].encrypt(string: plainText4)
                
                let receiverSession2 = try chat2.startNewSessionAsReceiver(senderCard: card1, ratchetMessage: cipherText2, enablePostQuantum: i == 1)
                let receiverSession3 = try chat3.startNewSessionAsReceiver(senderCard: card1, ratchetMessage: cipherText3, enablePostQuantum: i == 1)
                let receiverSession4 = try chat4.startNewSessionAsReceiver(senderCard: card1, ratchetMessage: cipherText4, enablePostQuantum: i == 1)
                
                let decryptedMessage2 = try receiverSession2.decryptString(from: cipherText2)
                let decryptedMessage3 = try receiverSession3.decryptString(from: cipherText3)
                let decryptedMessage4 = try receiverSession4.decryptString(from: cipherText4)
                
                XCTAssert(decryptedMessage2 == plainText2)
                XCTAssert(decryptedMessage3 == plainText3)
                XCTAssert(decryptedMessage4 == plainText4)
                
                try Utils.encryptDecrypt100Times(senderSession: sessions[0], receiverSession: receiverSession2)
                try Utils.encryptDecrypt100Times(senderSession: sessions[1], receiverSession: receiverSession3)
                try Utils.encryptDecrypt100Times(senderSession: sessions[2], receiverSession: receiverSession4)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
}
