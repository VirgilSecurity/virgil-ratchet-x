//
//  SignedPublicKey.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/18/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

@objc(VSRSignedPublicKey) public final class SignedPublicKey: NSObject, Decodable {
    @objc public let publicKey: Data
    @objc public let signature: Data
}
