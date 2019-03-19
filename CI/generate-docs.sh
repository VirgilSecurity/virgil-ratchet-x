gem install jazzy

jazzy \
--author "Virgil Security" \
--author_url "https://virgilsecurity.com/" \
--xcodebuild-arguments -scheme,"VirgilSDKRatchet macOS" \
--module "VirgilSDKRatchet" \
--output "${OUTPUT}" \
--hide-documentation-coverage \
--theme apple
