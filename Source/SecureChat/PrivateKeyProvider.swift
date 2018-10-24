//
//  PrivateKeyProvider.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/19/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

@objc(VSRPrivateKeyProvider) public protocol PrivateKeyProvider: class {
    @objc func getPrivateKey(withId id: Data) throws -> Data
}
