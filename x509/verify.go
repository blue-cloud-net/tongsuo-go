package x509

import "github.com/blue-cloud-net/tongsuo-go/internal/core"

// Certificate verification codes follow the Tongsuo 8.4 X509_V_* ABI.
const (
	// VerifyOK 是 X509_V_OK 验证结果码（0）。
	//
	// VerifyOK is the X509_V_OK verification result (0).
	VerifyOK = 0
	// VerifyUnspecified 是 X509_V_ERR_UNSPECIFIED 验证结果码（1）。
	//
	// VerifyUnspecified is the X509_V_ERR_UNSPECIFIED verification result (1).
	VerifyUnspecified = 1
	// VerifyUnableToGetIssuerCert 是 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT 验证结果码（2）。
	//
	// VerifyUnableToGetIssuerCert is the X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT verification result (2).
	VerifyUnableToGetIssuerCert = 2
	// VerifyUnableToGetCRL 是 X509_V_ERR_UNABLE_TO_GET_CRL 验证结果码（3）。
	//
	// VerifyUnableToGetCRL is the X509_V_ERR_UNABLE_TO_GET_CRL verification result (3).
	VerifyUnableToGetCRL = 3
	// VerifyUnableToDecryptCertSignature 是 X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE 验证结果码（4）。
	//
	// VerifyUnableToDecryptCertSignature is the X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE verification result (4).
	VerifyUnableToDecryptCertSignature = 4
	// VerifyUnableToDecryptCRLSignature 是 X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE 验证结果码（5）。
	//
	// VerifyUnableToDecryptCRLSignature is the X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE verification result (5).
	VerifyUnableToDecryptCRLSignature = 5
	// VerifyUnableToDecodeIssuerPublicKey 是 X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY 验证结果码（6）。
	//
	// VerifyUnableToDecodeIssuerPublicKey is the X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY verification result (6).
	VerifyUnableToDecodeIssuerPublicKey = 6
	// VerifyCertSignatureFailure 是 X509_V_ERR_CERT_SIGNATURE_FAILURE 验证结果码（7）。
	//
	// VerifyCertSignatureFailure is the X509_V_ERR_CERT_SIGNATURE_FAILURE verification result (7).
	VerifyCertSignatureFailure = 7
	// VerifyCRLSignatureFailure 是 X509_V_ERR_CRL_SIGNATURE_FAILURE 验证结果码（8）。
	//
	// VerifyCRLSignatureFailure is the X509_V_ERR_CRL_SIGNATURE_FAILURE verification result (8).
	VerifyCRLSignatureFailure = 8
	// VerifyCertNotYetValid 是 X509_V_ERR_CERT_NOT_YET_VALID 验证结果码（9）。
	//
	// VerifyCertNotYetValid is the X509_V_ERR_CERT_NOT_YET_VALID verification result (9).
	VerifyCertNotYetValid = 9
	// VerifyCertHasExpired 是 X509_V_ERR_CERT_HAS_EXPIRED 验证结果码（10）。
	//
	// VerifyCertHasExpired is the X509_V_ERR_CERT_HAS_EXPIRED verification result (10).
	VerifyCertHasExpired = 10
	// VerifyCRLNotYetValid 是 X509_V_ERR_CRL_NOT_YET_VALID 验证结果码（11）。
	//
	// VerifyCRLNotYetValid is the X509_V_ERR_CRL_NOT_YET_VALID verification result (11).
	VerifyCRLNotYetValid = 11
	// VerifyCRLHasExpired 是 X509_V_ERR_CRL_HAS_EXPIRED 验证结果码（12）。
	//
	// VerifyCRLHasExpired is the X509_V_ERR_CRL_HAS_EXPIRED verification result (12).
	VerifyCRLHasExpired = 12
	// VerifyErrorInCertNotBeforeField 是 X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD 验证结果码（13）。
	//
	// VerifyErrorInCertNotBeforeField is the X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD verification result (13).
	VerifyErrorInCertNotBeforeField = 13
	// VerifyErrorInCertNotAfterField 是 X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD 验证结果码（14）。
	//
	// VerifyErrorInCertNotAfterField is the X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD verification result (14).
	VerifyErrorInCertNotAfterField = 14
	// VerifyErrorInCRLLastUpdateField 是 X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD 验证结果码（15）。
	//
	// VerifyErrorInCRLLastUpdateField is the X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD verification result (15).
	VerifyErrorInCRLLastUpdateField = 15
	// VerifyErrorInCRLNextUpdateField 是 X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD 验证结果码（16）。
	//
	// VerifyErrorInCRLNextUpdateField is the X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD verification result (16).
	VerifyErrorInCRLNextUpdateField = 16
	// VerifyOutOfMem 是 X509_V_ERR_OUT_OF_MEM 验证结果码（17）。
	//
	// VerifyOutOfMem is the X509_V_ERR_OUT_OF_MEM verification result (17).
	VerifyOutOfMem = 17
	// VerifyDepthZeroSelfSignedCert 是 X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT 验证结果码（18）。
	//
	// VerifyDepthZeroSelfSignedCert is the X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT verification result (18).
	VerifyDepthZeroSelfSignedCert = 18
	// VerifySelfSignedCertInChain 是 X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN 验证结果码（19）。
	//
	// VerifySelfSignedCertInChain is the X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN verification result (19).
	VerifySelfSignedCertInChain = 19
	// VerifyUnableToGetIssuerCertLocally 是 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY 验证结果码（20）。
	//
	// VerifyUnableToGetIssuerCertLocally is the X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY verification result (20).
	VerifyUnableToGetIssuerCertLocally = 20
	// VerifyUnableToVerifyLeafSignature 是 X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE 验证结果码（21）。
	//
	// VerifyUnableToVerifyLeafSignature is the X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE verification result (21).
	VerifyUnableToVerifyLeafSignature = 21
	// VerifyCertChainTooLong 是 X509_V_ERR_CERT_CHAIN_TOO_LONG 验证结果码（22）。
	//
	// VerifyCertChainTooLong is the X509_V_ERR_CERT_CHAIN_TOO_LONG verification result (22).
	VerifyCertChainTooLong = 22
	// VerifyCertRevoked 是 X509_V_ERR_CERT_REVOKED 验证结果码（23）。
	//
	// VerifyCertRevoked is the X509_V_ERR_CERT_REVOKED verification result (23).
	VerifyCertRevoked = 23
	// VerifyNoIssuerPublicKey 是 X509_V_ERR_NO_ISSUER_PUBLIC_KEY 验证结果码（24）。
	//
	// VerifyNoIssuerPublicKey is the X509_V_ERR_NO_ISSUER_PUBLIC_KEY verification result (24).
	VerifyNoIssuerPublicKey = 24
	// VerifyPathLengthExceeded 是 X509_V_ERR_PATH_LENGTH_EXCEEDED 验证结果码（25）。
	//
	// VerifyPathLengthExceeded is the X509_V_ERR_PATH_LENGTH_EXCEEDED verification result (25).
	VerifyPathLengthExceeded = 25
	// VerifyInvalidPurpose 是 X509_V_ERR_INVALID_PURPOSE 验证结果码（26）。
	//
	// VerifyInvalidPurpose is the X509_V_ERR_INVALID_PURPOSE verification result (26).
	VerifyInvalidPurpose = 26
	// VerifyCertUntrusted 是 X509_V_ERR_CERT_UNTRUSTED 验证结果码（27）。
	//
	// VerifyCertUntrusted is the X509_V_ERR_CERT_UNTRUSTED verification result (27).
	VerifyCertUntrusted = 27
	// VerifyCertRejected 是 X509_V_ERR_CERT_REJECTED 验证结果码（28）。
	//
	// VerifyCertRejected is the X509_V_ERR_CERT_REJECTED verification result (28).
	VerifyCertRejected = 28
	// VerifySubjectIssuerMismatch 是 X509_V_ERR_SUBJECT_ISSUER_MISMATCH 验证结果码（29）。
	//
	// VerifySubjectIssuerMismatch is the X509_V_ERR_SUBJECT_ISSUER_MISMATCH verification result (29).
	VerifySubjectIssuerMismatch = 29
	// VerifyAKIDSKIDMismatch 是 X509_V_ERR_AKID_SKID_MISMATCH 验证结果码（30）。
	//
	// VerifyAKIDSKIDMismatch is the X509_V_ERR_AKID_SKID_MISMATCH verification result (30).
	VerifyAKIDSKIDMismatch = 30
	// VerifyAKIDIssuerSerialMismatch 是 X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH 验证结果码（31）。
	//
	// VerifyAKIDIssuerSerialMismatch is the X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH verification result (31).
	VerifyAKIDIssuerSerialMismatch = 31
	// VerifyKeyUsageNoCertSign 是 X509_V_ERR_KEYUSAGE_NO_CERTSIGN 验证结果码（32）。
	//
	// VerifyKeyUsageNoCertSign is the X509_V_ERR_KEYUSAGE_NO_CERTSIGN verification result (32).
	VerifyKeyUsageNoCertSign = 32
	// VerifyUnableToGetCRLIssuer 是 X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER 验证结果码（33）。
	//
	// VerifyUnableToGetCRLIssuer is the X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER verification result (33).
	VerifyUnableToGetCRLIssuer = 33
	// VerifyUnhandledCriticalExtension 是 X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION 验证结果码（34）。
	//
	// VerifyUnhandledCriticalExtension is the X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION verification result (34).
	VerifyUnhandledCriticalExtension = 34
	// VerifyKeyUsageNoCRLSign 是 X509_V_ERR_KEYUSAGE_NO_CRL_SIGN 验证结果码（35）。
	//
	// VerifyKeyUsageNoCRLSign is the X509_V_ERR_KEYUSAGE_NO_CRL_SIGN verification result (35).
	VerifyKeyUsageNoCRLSign = 35
	// VerifyUnhandledCriticalCRLExtension 是 X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION 验证结果码（36）。
	//
	// VerifyUnhandledCriticalCRLExtension is the X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION verification result (36).
	VerifyUnhandledCriticalCRLExtension = 36
	// VerifyInvalidNonCA 是 X509_V_ERR_INVALID_NON_CA 验证结果码（37）。
	//
	// VerifyInvalidNonCA is the X509_V_ERR_INVALID_NON_CA verification result (37).
	VerifyInvalidNonCA = 37
	// VerifyProxyPathLengthExceeded 是 X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED 验证结果码（38）。
	//
	// VerifyProxyPathLengthExceeded is the X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED verification result (38).
	VerifyProxyPathLengthExceeded = 38
	// VerifyKeyUsageNoDigitalSignature 是 X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE 验证结果码（39）。
	//
	// VerifyKeyUsageNoDigitalSignature is the X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE verification result (39).
	VerifyKeyUsageNoDigitalSignature = 39
	// VerifyProxyCertificatesNotAllowed 是 X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED 验证结果码（40）。
	//
	// VerifyProxyCertificatesNotAllowed is the X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED verification result (40).
	VerifyProxyCertificatesNotAllowed = 40
	// VerifyInvalidExtension 是 X509_V_ERR_INVALID_EXTENSION 验证结果码（41）。
	//
	// VerifyInvalidExtension is the X509_V_ERR_INVALID_EXTENSION verification result (41).
	VerifyInvalidExtension = 41
	// VerifyInvalidPolicyExtension 是 X509_V_ERR_INVALID_POLICY_EXTENSION 验证结果码（42）。
	//
	// VerifyInvalidPolicyExtension is the X509_V_ERR_INVALID_POLICY_EXTENSION verification result (42).
	VerifyInvalidPolicyExtension = 42
	// VerifyNoExplicitPolicy 是 X509_V_ERR_NO_EXPLICIT_POLICY 验证结果码（43）。
	//
	// VerifyNoExplicitPolicy is the X509_V_ERR_NO_EXPLICIT_POLICY verification result (43).
	VerifyNoExplicitPolicy = 43
	// VerifyDifferentCRLScope 是 X509_V_ERR_DIFFERENT_CRL_SCOPE 验证结果码（44）。
	//
	// VerifyDifferentCRLScope is the X509_V_ERR_DIFFERENT_CRL_SCOPE verification result (44).
	VerifyDifferentCRLScope = 44
	// VerifyUnsupportedExtensionFeature 是 X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE 验证结果码（45）。
	//
	// VerifyUnsupportedExtensionFeature is the X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE verification result (45).
	VerifyUnsupportedExtensionFeature = 45
	// VerifyUnnestedResource 是 X509_V_ERR_UNNESTED_RESOURCE 验证结果码（46）。
	//
	// VerifyUnnestedResource is the X509_V_ERR_UNNESTED_RESOURCE verification result (46).
	VerifyUnnestedResource = 46
	// VerifyPermittedViolation 是 X509_V_ERR_PERMITTED_VIOLATION 验证结果码（47）。
	//
	// VerifyPermittedViolation is the X509_V_ERR_PERMITTED_VIOLATION verification result (47).
	VerifyPermittedViolation = 47
	// VerifyExcludedViolation 是 X509_V_ERR_EXCLUDED_VIOLATION 验证结果码（48）。
	//
	// VerifyExcludedViolation is the X509_V_ERR_EXCLUDED_VIOLATION verification result (48).
	VerifyExcludedViolation = 48
	// VerifySubtreeMinMax 是 X509_V_ERR_SUBTREE_MINMAX 验证结果码（49）。
	//
	// VerifySubtreeMinMax is the X509_V_ERR_SUBTREE_MINMAX verification result (49).
	VerifySubtreeMinMax = 49
	// VerifyApplicationVerification 是 X509_V_ERR_APPLICATION_VERIFICATION 验证结果码（50）。
	//
	// VerifyApplicationVerification is the X509_V_ERR_APPLICATION_VERIFICATION verification result (50).
	VerifyApplicationVerification = 50
	// VerifyUnsupportedConstraintType 是 X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE 验证结果码（51）。
	//
	// VerifyUnsupportedConstraintType is the X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE verification result (51).
	VerifyUnsupportedConstraintType = 51
	// VerifyUnsupportedConstraintSyntax 是 X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX 验证结果码（52）。
	//
	// VerifyUnsupportedConstraintSyntax is the X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX verification result (52).
	VerifyUnsupportedConstraintSyntax = 52
	// VerifyUnsupportedNameSyntax 是 X509_V_ERR_UNSUPPORTED_NAME_SYNTAX 验证结果码（53）。
	//
	// VerifyUnsupportedNameSyntax is the X509_V_ERR_UNSUPPORTED_NAME_SYNTAX verification result (53).
	VerifyUnsupportedNameSyntax = 53
	// VerifyCRLPathValidationError 是 X509_V_ERR_CRL_PATH_VALIDATION_ERROR 验证结果码（54）。
	//
	// VerifyCRLPathValidationError is the X509_V_ERR_CRL_PATH_VALIDATION_ERROR verification result (54).
	VerifyCRLPathValidationError = 54
	// VerifyPathLoop 是 X509_V_ERR_PATH_LOOP 验证结果码（55）。
	//
	// VerifyPathLoop is the X509_V_ERR_PATH_LOOP verification result (55).
	VerifyPathLoop = 55
	// VerifySuiteBInvalidVersion 是 X509_V_ERR_SUITE_B_INVALID_VERSION 验证结果码（56）。
	//
	// VerifySuiteBInvalidVersion is the X509_V_ERR_SUITE_B_INVALID_VERSION verification result (56).
	VerifySuiteBInvalidVersion = 56
	// VerifySuiteBInvalidAlgorithm 是 X509_V_ERR_SUITE_B_INVALID_ALGORITHM 验证结果码（57）。
	//
	// VerifySuiteBInvalidAlgorithm is the X509_V_ERR_SUITE_B_INVALID_ALGORITHM verification result (57).
	VerifySuiteBInvalidAlgorithm = 57
	// VerifySuiteBInvalidCurve 是 X509_V_ERR_SUITE_B_INVALID_CURVE 验证结果码（58）。
	//
	// VerifySuiteBInvalidCurve is the X509_V_ERR_SUITE_B_INVALID_CURVE verification result (58).
	VerifySuiteBInvalidCurve = 58
	// VerifySuiteBInvalidSignatureAlgorithm 是 X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM 验证结果码（59）。
	//
	// VerifySuiteBInvalidSignatureAlgorithm is the X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM verification result (59).
	VerifySuiteBInvalidSignatureAlgorithm = 59
	// VerifySuiteBLoSNotAllowed 是 X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED 验证结果码（60）。
	//
	// VerifySuiteBLoSNotAllowed is the X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED verification result (60).
	VerifySuiteBLoSNotAllowed = 60
	// VerifySuiteBCannotSignP384WithP256 是 X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 验证结果码（61）。
	//
	// VerifySuiteBCannotSignP384WithP256 is the X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 verification result (61).
	VerifySuiteBCannotSignP384WithP256 = 61
	// VerifyHostnameMismatch 是 X509_V_ERR_HOSTNAME_MISMATCH 验证结果码（62）。
	//
	// VerifyHostnameMismatch is the X509_V_ERR_HOSTNAME_MISMATCH verification result (62).
	VerifyHostnameMismatch = 62
	// VerifyEmailMismatch 是 X509_V_ERR_EMAIL_MISMATCH 验证结果码（63）。
	//
	// VerifyEmailMismatch is the X509_V_ERR_EMAIL_MISMATCH verification result (63).
	VerifyEmailMismatch = 63
	// VerifyIPAddressMismatch 是 X509_V_ERR_IP_ADDRESS_MISMATCH 验证结果码（64）。
	//
	// VerifyIPAddressMismatch is the X509_V_ERR_IP_ADDRESS_MISMATCH verification result (64).
	VerifyIPAddressMismatch = 64
	// VerifyDANENoMatch 是 X509_V_ERR_DANE_NO_MATCH 验证结果码（65）。
	//
	// VerifyDANENoMatch is the X509_V_ERR_DANE_NO_MATCH verification result (65).
	VerifyDANENoMatch = 65
	// VerifyEEKeyTooSmall 是 X509_V_ERR_EE_KEY_TOO_SMALL 验证结果码（66）。
	//
	// VerifyEEKeyTooSmall is the X509_V_ERR_EE_KEY_TOO_SMALL verification result (66).
	VerifyEEKeyTooSmall = 66
	// VerifyCAKeyTooSmall 是 X509_V_ERR_CA_KEY_TOO_SMALL 验证结果码（67）。
	//
	// VerifyCAKeyTooSmall is the X509_V_ERR_CA_KEY_TOO_SMALL verification result (67).
	VerifyCAKeyTooSmall = 67
	// VerifyCAMDTooWeak 是 X509_V_ERR_CA_MD_TOO_WEAK 验证结果码（68）。
	//
	// VerifyCAMDTooWeak is the X509_V_ERR_CA_MD_TOO_WEAK verification result (68).
	VerifyCAMDTooWeak = 68
	// VerifyInvalidCall 是 X509_V_ERR_INVALID_CALL 验证结果码（69）。
	//
	// VerifyInvalidCall is the X509_V_ERR_INVALID_CALL verification result (69).
	VerifyInvalidCall = 69
	// VerifyStoreLookup 是 X509_V_ERR_STORE_LOOKUP 验证结果码（70）。
	//
	// VerifyStoreLookup is the X509_V_ERR_STORE_LOOKUP verification result (70).
	VerifyStoreLookup = 70
	// VerifyNoValidSCTS 是 X509_V_ERR_NO_VALID_SCTS 验证结果码（71）。
	//
	// VerifyNoValidSCTS is the X509_V_ERR_NO_VALID_SCTS verification result (71).
	VerifyNoValidSCTS = 71
	// VerifyProxySubjectNameViolation 是 X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION 验证结果码（72）。
	//
	// VerifyProxySubjectNameViolation is the X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION verification result (72).
	VerifyProxySubjectNameViolation = 72
	// VerifyOCSPVerifyNeeded 是 X509_V_ERR_OCSP_VERIFY_NEEDED 验证结果码（73）。
	//
	// VerifyOCSPVerifyNeeded is the X509_V_ERR_OCSP_VERIFY_NEEDED verification result (73).
	VerifyOCSPVerifyNeeded = 73
	// VerifyOCSPVerifyFailed 是 X509_V_ERR_OCSP_VERIFY_FAILED 验证结果码（74）。
	//
	// VerifyOCSPVerifyFailed is the X509_V_ERR_OCSP_VERIFY_FAILED verification result (74).
	VerifyOCSPVerifyFailed = 74
	// VerifyOCSPCertUnknown 是 X509_V_ERR_OCSP_CERT_UNKNOWN 验证结果码（75）。
	//
	// VerifyOCSPCertUnknown is the X509_V_ERR_OCSP_CERT_UNKNOWN verification result (75).
	VerifyOCSPCertUnknown = 75
	// VerifyUnsupportedSignatureAlgorithm 是 X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM 验证结果码（76）。
	//
	// VerifyUnsupportedSignatureAlgorithm is the X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM verification result (76).
	VerifyUnsupportedSignatureAlgorithm = 76
	// VerifySignatureAlgorithmMismatch 是 X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH 验证结果码（77）。
	//
	// VerifySignatureAlgorithmMismatch is the X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH verification result (77).
	VerifySignatureAlgorithmMismatch = 77
	// VerifySignatureAlgorithmInconsistency 是 X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY 验证结果码（78）。
	//
	// VerifySignatureAlgorithmInconsistency is the X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY verification result (78).
	VerifySignatureAlgorithmInconsistency = 78
	// VerifyInvalidCA 是 X509_V_ERR_INVALID_CA 验证结果码（79）。
	//
	// VerifyInvalidCA is the X509_V_ERR_INVALID_CA verification result (79).
	VerifyInvalidCA = 79
	// VerifyPathLenInvalidForNonCA 是 X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA 验证结果码（80）。
	//
	// VerifyPathLenInvalidForNonCA is the X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA verification result (80).
	VerifyPathLenInvalidForNonCA = 80
	// VerifyPathLenWithoutKUKeyCertSign 是 X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN 验证结果码（81）。
	//
	// VerifyPathLenWithoutKUKeyCertSign is the X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN verification result (81).
	VerifyPathLenWithoutKUKeyCertSign = 81
	// VerifyKUKeyCertSignInvalidForNonCA 是 X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA 验证结果码（82）。
	//
	// VerifyKUKeyCertSignInvalidForNonCA is the X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA verification result (82).
	VerifyKUKeyCertSignInvalidForNonCA = 82
	// VerifyIssuerNameEmpty 是 X509_V_ERR_ISSUER_NAME_EMPTY 验证结果码（83）。
	//
	// VerifyIssuerNameEmpty is the X509_V_ERR_ISSUER_NAME_EMPTY verification result (83).
	VerifyIssuerNameEmpty = 83
	// VerifySubjectNameEmpty 是 X509_V_ERR_SUBJECT_NAME_EMPTY 验证结果码（84）。
	//
	// VerifySubjectNameEmpty is the X509_V_ERR_SUBJECT_NAME_EMPTY verification result (84).
	VerifySubjectNameEmpty = 84
	// VerifyMissingAuthorityKeyIdentifier 是 X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER 验证结果码（85）。
	//
	// VerifyMissingAuthorityKeyIdentifier is the X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER verification result (85).
	VerifyMissingAuthorityKeyIdentifier = 85
	// VerifyMissingSubjectKeyIdentifier 是 X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER 验证结果码（86）。
	//
	// VerifyMissingSubjectKeyIdentifier is the X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER verification result (86).
	VerifyMissingSubjectKeyIdentifier = 86
	// VerifyEmptySubjectAltName 是 X509_V_ERR_EMPTY_SUBJECT_ALT_NAME 验证结果码（87）。
	//
	// VerifyEmptySubjectAltName is the X509_V_ERR_EMPTY_SUBJECT_ALT_NAME verification result (87).
	VerifyEmptySubjectAltName = 87
	// VerifyEmptySubjectSANNotCritical 是 X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL 验证结果码（88）。
	//
	// VerifyEmptySubjectSANNotCritical is the X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL verification result (88).
	VerifyEmptySubjectSANNotCritical = 88
	// VerifyCABasicConstraintsNotCritical 是 X509_V_ERR_CA_BCONS_NOT_CRITICAL 验证结果码（89）。
	//
	// VerifyCABasicConstraintsNotCritical is the X509_V_ERR_CA_BCONS_NOT_CRITICAL verification result (89).
	VerifyCABasicConstraintsNotCritical = 89
	// VerifyAuthorityKeyIdentifierCritical 是 X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL 验证结果码（90）。
	//
	// VerifyAuthorityKeyIdentifierCritical is the X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL verification result (90).
	VerifyAuthorityKeyIdentifierCritical = 90
	// VerifySubjectKeyIdentifierCritical 是 X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL 验证结果码（91）。
	//
	// VerifySubjectKeyIdentifierCritical is the X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL verification result (91).
	VerifySubjectKeyIdentifierCritical = 91
	// VerifyCACertMissingKeyUsage 是 X509_V_ERR_CA_CERT_MISSING_KEY_USAGE 验证结果码（92）。
	//
	// VerifyCACertMissingKeyUsage is the X509_V_ERR_CA_CERT_MISSING_KEY_USAGE verification result (92).
	VerifyCACertMissingKeyUsage = 92
	// VerifyExtensionsRequireVersion3 是 X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 验证结果码（93）。
	//
	// VerifyExtensionsRequireVersion3 is the X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 verification result (93).
	VerifyExtensionsRequireVersion3 = 93
	// VerifyECKeyExplicitParams 是 X509_V_ERR_EC_KEY_EXPLICIT_PARAMS 验证结果码（94）。
	//
	// VerifyECKeyExplicitParams is the X509_V_ERR_EC_KEY_EXPLICIT_PARAMS verification result (94).
	VerifyECKeyExplicitParams = 94
)

// VerifyErrorMessage 返回原生证书验证结果的可读解释，包括未知错误码。
//
// VerifyErrorMessage returns native certificate verification text, including unknown codes.
func VerifyErrorMessage(code int) string { return core.VerifyErrorMessage(code) }
