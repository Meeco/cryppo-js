export enum CipherStrategy {
  AES_ECB = 'AES-ECB',
  AES_CBC = 'AES-CBC',
  AES_CFB = 'AES-CFB',
  AES_OFB = 'AES-OFB',
  AES_CTR = 'AES-CTR',
  AES_GCM = 'AES-GCM',
  DES_ECB = 'DES-ECB',
  DES_CBC = 'DES-CBC',
  // Not currently suppoted as they have different key size (256 not supported)
  // THREE_DES_ECB = '3DES-ECB',
  // THREE_DES_CBC = '3DES-CBC',
}

/*
 * Convert an algorithm from a serialized payload (e.g Aes256Gcm.data.artifacts) in the ruby lib's naming
 * scheme to one that can be used by forge
 */
export const strategyToAlgorithm = (algorithm: string): CipherStrategy =>
  algorithm
    .split(/[0-9]+/)
    .map((v) => v.toUpperCase())
    .join('-') as CipherStrategy;
