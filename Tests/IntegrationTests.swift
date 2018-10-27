//
//  IntegrationTests.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/28/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import XCTest
import VirgilSDK
import VirgilCryptoApiImpl
import VSCRatchet
@testable import VirgilSDKRatchet

class IntegrationTests: XCTestCase {
    
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
        let senderIdentityKeyPair = try! crypto.generateKeyPair()
        
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
        
        let receiverLongTermKeysStorage = FakeLongTermKeysStorage(db: [:])
        let receiverOneTimeKeysStorage = FakeOneTimeKeysStorage(db: [:])
        
        let fakeClient = FakeRamClient(cardManager: cardManager)
        
        let receiverKeysRotator = KeysRotator(identityPrivateKey: receiverIdentityKeyPair.privateKey, identityCardId: receiverCard.identifier, longTermKeysStorage: receiverLongTermKeysStorage, oneTimeKeysStorage: receiverOneTimeKeysStorage, client: fakeClient)
        
        
        let senderSecureChat = SecureChat(identityPrivateKey: senderIdentityKeyPair.privateKey,
                                          accessTokenProvider: senderTokenProvider,
                                          client: fakeClient,
                                          longTermKeysStorage: FakeLongTermKeysStorage(db: [:]),
                                          oneTimeKeysStorage: FakeOneTimeKeysStorage(db: [:]),
                                          sessionStorage: FakeRamSessionStorage(),
                                          keysRotator: FakeKeysRotator())
        
        let receiverSecureChat = SecureChat(identityPrivateKey: receiverIdentityKeyPair.privateKey,
                                            accessTokenProvider: receiverTokenProvider,
                                            client: fakeClient,
                                            longTermKeysStorage: receiverLongTermKeysStorage,
                                            oneTimeKeysStorage: receiverOneTimeKeysStorage,
                                            sessionStorage: FakeRamSessionStorage(),
                                            keysRotator: receiverKeysRotator)
        
        return (senderCard, receiverCard, senderSecureChat, receiverSecureChat)
    }
    
    func test1() {
        let (senderCard, receiverCard, senderSecureChat, receiverSecureChat) = self.initChat()
        
        try! receiverSecureChat.rotateKeys().startSync().getResult()
        
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
}
