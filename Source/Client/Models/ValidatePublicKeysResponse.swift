//
//  ValidatePublicKeysResponse.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/18/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

@objc(VSRValidatePublicKeysResponse) public final class ValidatePublicKeysResponse: NSObject, Decodable {
    @objc public let usedLongTermKeyId: Data?
    @objc public let usedOneTimeKeysIds: [Data]
}
