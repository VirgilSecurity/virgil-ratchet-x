//
//  SignedPublicKey.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/18/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

public final class SignedPublicKey: NSObject, Decodable {
    public let publicKey: Data
    public let signature: Data
    
    internal init(publicKey: Data, signature: Data) {
        self.publicKey = publicKey
        self.signature = signature
    }
}
