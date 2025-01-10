import { PassportData } from '../../../common/src/utils/types';
import { findSubarrayIndex, formatMrz, hash } from './utils';
import { parseCertificateSimple } from './certificate_parsing/parseCertificateSimple';
import {
    CertificateData,
    PublicKeyDetailsECDSA,
    PublicKeyDetailsRSA,
    PublicKeyDetailsRSAPSS,
} from './certificate_parsing/dataStructure';
import { hashAlgos } from '../constants/constants';
import { brutforceSignatureAlgorithm } from './brutForcePassportSignature';
import { DscCertificateMetaData, parseDscCertificateData } from './parseDscCertificateData';

export interface PassportMetadata {
    dataGroups: string;
    dg1HashFunction: string;
    dg1HashOffset: number;
    eContentSize: number;
    eContentHashFunction: string;
    eContentHashOffset: number;
    signedAttrSize: number;
    signedAttrHashFunction: string;
    signatureAlgorithm: string;
    saltLength: number;
    curveOrExponent: string;
    signatureAlgorithmBits: number;
    countryCode: string;
    cscaFound: boolean;
    cscaHashFunction: string;
    cscaSignature: string;
    cscaSaltLength: number;
    cscaCurveOrExponent: string;
    cscaSignatureAlgorithmBits: number;
    dsc: string;
}

function findHashSizeOfEContent(eContent: number[], signedAttr: number[]) {
    for (const hashFunction of hashAlgos) {
        const hashValue = hash(hashFunction, eContent);
        const hashOffset = findSubarrayIndex(signedAttr, hashValue as number[]);
        if (hashOffset !== -1) {
            return { hashFunction, offset: hashOffset };
        }
    }
    return { hashFunction: 'unknown', offset: -1 };
}

function findDG1HashInEContent(
    mrz: string,
    eContent: number[]
): { hash: number[]; hashFunction: string; offset: number } | null {
    const formattedMrz = formatMrz(mrz);

    for (const hashFunction of hashAlgos) {
        const hashValue = hash(hashFunction, formattedMrz);
        const normalizedHash = (hashValue as number[]).map((byte) => (byte > 127 ? byte - 256 : byte));
        const hashOffset = findSubarrayIndex(eContent, normalizedHash);

        if (hashOffset !== -1) {
            return { hash: hashValue as number[], hashFunction, offset: hashOffset };
        }
    }
    return null;
}

export function getCountryCodeFromMrz(mrz: string): string {
    return mrz.substring(2, 5);
}

export function getCurveOrExponent(certData: CertificateData): string {
    if (certData.signatureAlgorithm === 'rsapss' || certData.signatureAlgorithm === 'rsa') {
        return (certData.publicKeyDetails as PublicKeyDetailsRSA).exponent;
    }
    return (certData.publicKeyDetails as PublicKeyDetailsECDSA).curve;
}

function getSimplePublicKeyDetails(certData: CertificateData): string {
    interface SimplePublicKeyDetails {
        exponent?: string;
        curve?: string;
        hashAlgorithm?: string;
        saltLength?: string;
    }
    const simplePublicKeyDetails: SimplePublicKeyDetails = {};
    if (certData.signatureAlgorithm === 'rsapss' || certData.signatureAlgorithm === 'rsa') {
        simplePublicKeyDetails.exponent = (certData.publicKeyDetails as PublicKeyDetailsRSA).exponent;
        if (certData.signatureAlgorithm === 'rsapss') {
            simplePublicKeyDetails.hashAlgorithm = (
                certData.publicKeyDetails as PublicKeyDetailsRSAPSS
            ).hashAlgorithm;
            simplePublicKeyDetails.saltLength = (
                certData.publicKeyDetails as PublicKeyDetailsRSAPSS
            ).saltLength;
        }
    } else if (certData.signatureAlgorithm === 'ecdsa') {
        simplePublicKeyDetails.curve = (certData.publicKeyDetails as PublicKeyDetailsECDSA).curve;
    }
    return JSON.stringify(simplePublicKeyDetails);
}



export function parsePassportData(passportData: PassportData): PassportMetadata {
    const dg1HashInfo = passportData.mrz
        ? findDG1HashInEContent(passportData.mrz, passportData.eContent)
        : null;

    const dg1HashFunction = dg1HashInfo?.hashFunction || 'unknown';
    const dg1HashOffset = dg1HashInfo?.offset || 0;

    const { hashFunction: eContentHashFunction, offset: eContentHashOffset } = findHashSizeOfEContent(
        passportData.eContent,
        passportData.signedAttr
    );

    const brutForcedPublicKeyDetails = brutforceSignatureAlgorithm(passportData);

    let parsedDsc = null;
    let dscSignatureAlgorithmBits = 0;

    let brutForcedPublicKeyDetailsDsc: DscCertificateMetaData;

    if (passportData.dsc) {
        parsedDsc = parseCertificateSimple(passportData.dsc);
        dscSignatureAlgorithmBits = parseInt(parsedDsc.publicKeyDetails?.bits || '0');

        brutForcedPublicKeyDetailsDsc = parseDscCertificateData(parsedDsc)


    }

    return {
        dataGroups:
            passportData.dgPresents
                ?.toString()
                .split(',')
                .map((item) => item.replace('DG', ''))
                .join(',') || 'None',
        dg1HashFunction,
        dg1HashOffset,
        eContentSize: passportData.eContent?.length || 0,
        eContentHashFunction,
        eContentHashOffset,
        signedAttrSize: passportData.signedAttr?.length || 0,
        signedAttrHashFunction: brutForcedPublicKeyDetails.hashAlgorithm,
        signatureAlgorithm: brutForcedPublicKeyDetails.signatureAlgorithm,
        saltLength: brutForcedPublicKeyDetails.saltLength,
        curveOrExponent: parsedDsc ? getCurveOrExponent(parsedDsc) : 'unknown',
        signatureAlgorithmBits: dscSignatureAlgorithmBits,
        countryCode: passportData.mrz ? getCountryCodeFromMrz(passportData.mrz) : 'unknown',
        cscaFound: brutForcedPublicKeyDetailsDsc.cscaFound,
        cscaHashFunction: brutForcedPublicKeyDetailsDsc.cscaHashAlgorithm,
        cscaSignature: brutForcedPublicKeyDetailsDsc.cscaSignatureAlgorithm,
        cscaSaltLength: brutForcedPublicKeyDetailsDsc.cscaSaltLength,
        cscaCurveOrExponent: brutForcedPublicKeyDetailsDsc.cscaCurveOrExponent,
        cscaSignatureAlgorithmBits: brutForcedPublicKeyDetailsDsc.cscaSignatureAlgorithmBits,
        dsc: passportData.dsc,
    };
}