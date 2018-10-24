//
//  ValidatePublicKeysResponse.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/18/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

public final class ValidatePublicKeysResponse: NSObject, Decodable {
    public let usedLongTermKeyId: Data?
    public let usedOneTimeKeysIds: [Data]
}
