//
//  VirgilSDKRatchetTests.swift
//  VirgilSDKRatchetTests
//
//  Created by Oleksandr Deundiak on 10/17/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import XCTest
import VirgilSDK
import VirgilCryptoApiImpl
import VSCRatchet
@testable import VirgilSDKRatchet

class VirgilSDKRatchetTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func initChat() -> (Card, Card, SecureChat, SecureChat) {
        let testConfig = TestConfig.readFromBundle()
        
        let crypto = VirgilCrypto(defaultKeyType: .EC_CURVE25519, useSHA256Fingerprints: false)
        let receiverIdentityKeyPair = try! crypto.generateKeyPair()
        let receiverIdentityPublicKey = CUtils.extractRawPublicKey(crypto.exportPublicKey(receiverIdentityKeyPair.publicKey))
        let receiverIdentityPrivateKey = CUtils.extractRawPrivateKey(crypto.exportPrivateKey(receiverIdentityKeyPair.privateKey))
        let receiverLongTermKeyPair = try! crypto.generateKeyPair()
        let receiverLongTermPublicKey = CUtils.extractRawPublicKey(crypto.exportPublicKey(receiverLongTermKeyPair.publicKey))
        let receiverLongTermPrivateKey = CUtils.extractRawPrivateKey(crypto.exportPrivateKey(receiverLongTermKeyPair.privateKey))
        let receiverOneTimeKeyPair = try! crypto.generateKeyPair()
        let receiverOneTimePublicKey = CUtils.extractRawPublicKey(crypto.exportPublicKey(receiverOneTimeKeyPair.publicKey))
        let receiverOneTimePrivateKey = CUtils.extractRawPrivateKey(crypto.exportPrivateKey(receiverOneTimeKeyPair.privateKey))
        let senderIdentityKeyPair = try! crypto.generateKeyPair()
        let senderIdentityPublicKey = CUtils.extractRawPublicKey(crypto.exportPublicKey(senderIdentityKeyPair.publicKey))
        let senderIdentityPrivateKey = CUtils.extractRawPrivateKey(crypto.exportPrivateKey(senderIdentityKeyPair.privateKey))
        
        let senderIdentity = NSUUID().uuidString
        let receiverIdentity = NSUUID().uuidString
        
        let receiverTokenProvider = CallbackJwtProvider(getJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!)
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: receiverIdentity), nil)
        })
        
        let senderTokenProvider = CallbackJwtProvider(getJwtCallback: { context, completion in
            let privateKey = try! crypto.importPrivateKey(from: Data(base64Encoded: testConfig.ApiPrivateKey)!)
            
            let generator = JwtGenerator(apiKey: privateKey, apiPublicKeyIdentifier: testConfig.ApiPublicKeyId, accessTokenSigner: VirgilAccessTokenSigner(), appId: testConfig.AppId, ttl: 10050)
            
            completion(try! generator.generateToken(identity: senderIdentity), nil)
        })
        
        let cardVerifier = VirgilCardVerifier(cardCrypto: VirgilCardCrypto())!
        cardVerifier.verifyVirgilSignature = false
        let cardManagerParams = CardManagerParams(cardCrypto: VirgilCardCrypto(), accessTokenProvider: receiverTokenProvider, cardVerifier: cardVerifier)
        cardManagerParams.cardClient = CardClient(serviceUrl: URL(string: testConfig.ServiceURL)!)
        
        let cardManager = CardManager(params: cardManagerParams)
        
        let receiverCard = try! cardManager.publishCard(privateKey: receiverIdentityKeyPair.privateKey, publicKey: receiverIdentityKeyPair.publicKey).startSync().getResult()
        let senderCard = try! cardManager.publishCard(privateKey: senderIdentityKeyPair.privateKey, publicKey: senderIdentityKeyPair.publicKey).startSync().getResult()
        
        let publicKeySet = PublicKeySet(identityPublicKey: receiverIdentityPublicKey, longtermPublicKey: SignedPublicKey(publicKey: receiverLongTermPublicKey, signature: try! crypto.generateSignature(of: receiverLongTermPublicKey, using: receiverIdentityKeyPair.privateKey)), onetimePublicKey: receiverOneTimePublicKey)
        
        let fakeClient = FakeClient(publicKeySet: publicKeySet)
//        let fakeClient = FakeRamClient(cardManager: cardManager)
        let fakePrivateKeyProvider = FakePrivateKeyProvider(db: [
            receiverIdentityPublicKey: receiverIdentityPrivateKey,
            receiverLongTermPublicKey: receiverLongTermPrivateKey,
            receiverOneTimePublicKey: receiverOneTimePrivateKey
            ])
        
        let senderSecureChat = SecureChat(identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          accessTokenProvider: senderTokenProvider,
                                          client: fakeClient, privateKeyProvider: fakePrivateKeyProvider, sessionStorage: FakeRamSessionStorage())
        
        let receiverSecureChat = SecureChat(identityPrivateKey: receiverIdentityKeyPair.privateKey, accessTokenProvider: receiverTokenProvider, client: fakeClient, privateKeyProvider: fakePrivateKeyProvider, sessionStorage: FakeRamSessionStorage())
        
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }

    func test1() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        let senderSession = try! senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard)
        
        let plainText = UUID().uuidString
        let cipherText = try! senderSession.encrypt(message: plainText)
        
        let receiverSession = try! receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, message: cipherText)
        
        let ratchetMessage = vscr_ratchet_message_deserialize(CUtils.bindForRead(data: cipherText), nil)!
        
        let decryptedMessage = try! receiverSession.decrypt(message: ratchetMessage)
        
        XCTAssert(decryptedMessage == plainText)
        
        for _ in 0..<100 {
            let sender: SecureSession
            let receiver: SecureSession
            
            if Bool.random() {
                sender = senderSession
                receiver = receiverSession
            }
            else {
                sender = receiverSession
                receiver = senderSession
            }
            
            let plainText = UUID().uuidString
            
            let encryptedData = try! sender.encrypt(message: plainText)
            
            let message = vscr_ratchet_message_deserialize(CUtils.bindForRead(data: encryptedData), nil)!
            
            let decryptedMessage = try! receiver.decrypt(message: message)
            
            vscr_ratchet_message_delete(message)
            
            XCTAssert(decryptedMessage == plainText)
        }
    }
    
    func test2() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        let senderSession = try! senderSecureChat.startNewSessionAsSender(receiverCard: receiverCard)
        
        XCTAssert(senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity) != nil)
        
        let plainText = UUID().uuidString
        let cipherText = try! senderSession.encrypt(message: plainText)
        
        let receiverSession = try! receiverSecureChat.startNewSessionAsReceiver(senderCard: senderCard, message: cipherText)
        
        XCTAssert(receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity) != nil)
        
        let ratchetMessage = vscr_ratchet_message_deserialize(CUtils.bindForRead(data: cipherText), nil)!
        
        let decryptedMessage = try! receiverSession.decrypt(message: ratchetMessage)
        
        XCTAssert(decryptedMessage == plainText)
        
        for _ in 0..<100 {
            let sender: SecureSession
            let receiver: SecureSession
            
            if Bool.random() {
                sender = senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity)!
                receiver = receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity)!
            }
            else {
                sender = receiverSecureChat.existingSession(withParticpantIdentity: senderCard.identity)!
                receiver = senderSecureChat.existingSession(withParticpantIdentity: receiverCard.identity)!
            }
            
            let plainText = UUID().uuidString
            
            let encryptedData = try! sender.encrypt(message: plainText)
            
            let message = vscr_ratchet_message_deserialize(CUtils.bindForRead(data: encryptedData), nil)!
            
            let decryptedMessage = try! receiver.decrypt(message: message)
            
            vscr_ratchet_message_delete(message)
            
            XCTAssert(decryptedMessage == plainText)
        }
    }
}
