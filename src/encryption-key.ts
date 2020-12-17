import { random } from 'node-forge';
import { binaryStringToBytes, bytesToBinaryString, decodeSafe64, encodeSafe64 } from './util';

/**
 * A key that can be used to encrypt and decrypt data
 * This wrapper ensures that keys can be safely serialized as JSON (by encoding them as URL-Safe Base64)
 * and avoids confusion when dealing with converting to and from this encoded format.
 */
export class EncryptionKey {
  public static fromSerialized(value: string) {
    this.checkStringValue(value);
    return new EncryptionKey(binaryStringToBytes(decodeSafe64(value)));
  }

  public static fromBytes(bytes: Uint8Array) {
    this.checkBytesValue(bytes);
    return new EncryptionKey(bytes);
  }

  public static generateRandom(length: number = 32) {
    return new EncryptionKey(binaryStringToBytes(random.getBytesSync(length)));
  }

  private static checkStringValue(value: string) {
    value = value.trim();
    if (!value) {
      throw new Error('bytes are empty or undefined');
    }
  }

  private static checkBytesValue(value: Uint8Array) {
    if (!value || value.length === 0) {
      throw new Error('bytes are empty or undefined');
    }
  }

  /**
   * The constructor is intentionally private as we want the user ot be explicit as to whether the value coming
   * in is raw bytes or a base64 encoded version.
   *
   * @param value  Value as binary string. Avoid outputting to console but should be used for actual encryption.
   */
  private constructor(private readonly value: Uint8Array) {}

  /**
   * Encode a key in a human-readable and url-safe format.
   */
  get serialize() {
    return encodeSafe64(bytesToBinaryString(this.value));
  }

  get bytes() {
    return this.value;
  }
}
