// https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
// https://rhardih.io/2021/04/listing-the-contents-of-a-remote-zip-archive-without-downloading-the-entire-file/

import fetch from "cross-fetch";
import { inflateRaw } from "pako";

// ZIP file signatures
const SIG_CD = 0x504b0102;
const SIG_LOCAL_FILE_HEADER = 0x504b0304;
const SIG_EOCD = 0x504b0506;
const SIG_DATA_DESCRIPTOR = 0x504b0708;

class RemoteZipError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
  }
}

export interface EndOfCentralDirectory {
  meta: Record<string, unknown>;
  data: {
    /** End of central directory signature = 0x06054b50 */
    signature: ArrayBuffer;
    /** Number of this disk (or 0xffff for ZIP64) */
    diskNumber: number;
    /** Disk where central directory starts (or 0xffff for ZIP64) */
    cdDisk: number;
    /** Number of central directory records on this disk (or 0xffff for ZIP64) */
    centralDirectoryDiskNumber: number;
    /** Number of central directory records on this disk (or 0xffff for ZIP64) */
    centralDirectoryRecordCount: number;
    /** Size of central directory (bytes) (or 0xffffffff for ZIP64) */
    centralDirectoryByteSize: number;
    /** Offset of start of central directory, relative to start of archive (or 0xffffffff for ZIP64) */
    centralDirectoryByteOffset: number;
    /** Comment length (n) */
    comment: string;
    /** Comment */
    commentLength: number;
  };
}

export interface CentralDirectoryRecord {
  meta: {
    /** Length of the entire record */
    length: number;
  };
  data: {
    /** Central directory file header signature = 0x02014b50 */
    signature: ArrayBuffer;
    /** Version of the program this ZIP was made by.
     *
     * Upper byte:
     * - 0 - MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
     * - 1 - Amiga
     * - 2 - OpenVMS
     * - 3 - UNIX
     * - 4 - VM/CMS
     * - 5 - Atari ST
     * - 6 - OS/2 H.P.F.S.
     * - 7 - Macintosh
     * - 8 - Z-System
     * - 9 - CP/M
     * - 10 - Windows NTFS
     * - 11 - MVS (OS/390 - Z/OS)
     * - 12 - VSE
     * - 13 - Acorn Risc
     * - 14 - VFAT
     * - 15 - alternate MVS
     * - 16 - BeOS
     * - 17 - Tandem
     * - 18 - OS/400
     * - 19 - OS/X (Darwin)
     * - 20 - 255: Unused
     */
    versionMadeBy: number;
    /** Version needed to extract (minimum) */
    versionToExtract: number;
    /** General purpose bit flag
     *
     * - Bit 00: encrypted file
     * - Bit 01: compression option
     * - Bit 02: compression option
     * - Bit 03: data descriptor
     * - Bit 04: enhanced deflation
     * - Bit 05: compressed patched data
     * - Bit 06: strong encryption
     * - Bit 07-10: unused
     * - Bit 11: language encoding
     * - Bit 12: reserved
     * - Bit 13: mask header values
     * - Bit 14-15: reserved
     */
    generalPurposeBitFlag: number;
    /** Compression method; e.g. none = 0, DEFLATE = 8 (or "\0x08\0x00")
     *
     * - 00: no compression
     * - 01: shrunk
     * - 02: reduced with compression factor 1
     * - 03: reduced with compression factor 2
     * - 04: reduced with compression factor 3
     * - 05: reduced with compression factor 4
     * - 06: imploded
     * - 07: reserved
     * - 08: deflated
     * - 09: enhanced deflated
     * - 10: PKWare DCL imploded
     * - 11: reserved
     * - 12: compressed using BZIP2
     * - 13: reserved
     * - 14: LZMA
     * - 15-17: reserved
     * - 18: compressed using IBM TERSE
     * - 19: IBM LZ77 z
     * - 98: PPMd version I, Rev 1
     */
    compressionMethod: number;
    /** File last modification time (DOS) */
    lastModifiedTime: number;
    /** File last modification date (DOS) */
    lastModifiedDate: number;
    /** CRC-32 of uncompressed data
     * Value computed over file data by CRC-32 algorithm with
     * 'magic number' 0xdebb20e3 (little endian)
     */
    crc32: number;
    /** Compressed size (or 0xffffffff for ZIP64) */
    compressedSize: number;
    /** Uncompressed size (or 0xffffffff for ZIP64) */
    uncompressedSize: number;
    /** File name length (n) */
    filenameLength: number;
    /** Extra field length (m) */
    extraFieldLength: number;
    /** File comment length (k) */
    fileCommentLength: number;
    /** Disk number where file starts */
    startingDiskNumber: number;
    /** Internal file attributes
     *
     * Bit 0: apparent ASCII/text file
     * Bit 1: reserved
     * Bit 2: control field records precede logical records
     * Bits 3-16: unused
     */
    internalFileAttributes: number;
    /** External file attributes (host-system dependent) */
    externalFileAttributes: number;
    /** Relative offset of local file header.
     * This is the number of bytes between the start of the first
     * disk on which the file occurs, and the start of the local file
     * header. This allows software reading the central directory to
     * locate the position of the file inside the ZIP file. */
    localFileHeaderRelativeOffset: number;
    /** File name */
    filename: string;
    /** Extra field
     *
     * Used to store additional information. The field consistes of a sequence of
     * header and data pairs, where the header has a 2 byte identifier and a 2 byte data size field.
     */
    extraField: ArrayBuffer;
    /** File comment */
    fileComment: string;
  };
}

export interface LocalFileHeader {
  meta: {
    compressedData: ArrayBuffer;
    /** If the bit at offset 3 (0x08) of the general-purpose flags field is set,
     * then the CRC-32 and file sizes are not known when the header is written.
     * The fields in the local header are filled with zero, and the CRC-32 and size are
     * appended in a 12-byte structure (optionally preceded by a 4-byte signature) immediately
     * after the compressed data */
    dataDescriptor?: {
      /** Optional data descriptor signature = 0x08074b50 */
      optionalSignature?: ArrayBuffer;
      /** CRC-32 of uncompressed data */
      crc32: number;
      /** Compressed size */
      compressedSize: number;
      /** Uncompressed size */
      uncompressedSize: number;
    };
  };
  data: {
    /** Local file header signature = 0x04034b50 (PK♥♦ or "PK\3\4") */
    signature: ArrayBuffer;
    /** Version needed to extract (minimum) */
    versionToExtract: number;
    /** General purpose bit flag  */
    generalPurposeBitFlag: number;
    /** Compression method; e.g. none = 0, DEFLATE = 8 (or "\0x08\0x00") */
    compressionMethod: number;
    /** File last modification time (DOS format) */
    lastModifiedTime: number;
    /** File last modification date (DOS format) */
    lastModifiedDate: number;
    /** CRC-32 of uncompressed data
     * Value computed over file data by CRC-32 algorithm with
     * 'magic number' 0xdebb20e3 (little endian)
     */
    crc32: number;
    /** Compressed size (or 0xffffffff for ZIP64) */
    compressedSize: number;
    /** Uncompressed size (or 0xffffffff for ZIP64) */
    uncompressedSize: number;
    /** File name length (n) */
    filenameLength: number;
    /** Extra field length (m) */
    extraFieldLength: number;
    /** File name */
    filename: string;
    /** Extra field */
    extraField: ArrayBuffer;
  };
}

export interface RemoteZipFile {
  filename: string;
  /** bytes */
  size: number;
  /** ISO timestamp without timezone (ZIP/DOS does not preserve timezones) */
  modified: string;
  /** File attributes of host system */
  attributes: number;
}

export class RemoteZip {
  contentLength: number;
  url: URL;
  centralDirectoryRecords: CentralDirectoryRecord[];
  endOfCentralDirectory: EndOfCentralDirectory | null;
  method: string;
  credentials: "include" | "omit" | "same-origin";

  constructor({
    contentLength,
    url,
    centralDirectoryRecords,
    endOfCentralDirectory,
    method,
    credentials = "same-origin",
  }: {
    contentLength: number;
    url: URL;
    centralDirectoryRecords: CentralDirectoryRecord[];
    endOfCentralDirectory: EndOfCentralDirectory | null;
    method: string;
    credentials: "include" | "omit" | "same-origin";
  }) {
    this.contentLength = contentLength;
    this.url = url;
    this.method = method;
    this.centralDirectoryRecords = centralDirectoryRecords;
    this.endOfCentralDirectory = endOfCentralDirectory;
    this.credentials = credentials;
  }

  public files(): RemoteZipFile[] {
    return this.centralDirectoryRecords.map((r) => ({
      filename: r.data.filename,
      size: r.data.uncompressedSize,
      modified: parseZipDatetime(
        r.data.lastModifiedDate,
        r.data.lastModifiedTime
      ),
      attributes: r.data.externalFileAttributes,
    }));
  }

  /** Gets a single uncompressed file in the remote ZIP. */
  // TODO: Return a ReadableStream instead of an ArrayBuffer so we don't need
  // to download the entire thing (to show video previews, for example)
  // Can't use WHATWG ReadableStream in node, so we avoid using streams until at least node-fetch v3
  // When cross-fetch upgrades to node-fetch v3, maybe? Testing is a PITA without it.
  // https://github.com/node-fetch/node-fetch/blob/main/docs/v3-LIMITS.md
  public async fetch(
    path: string,
    additionalHeaders?: Headers
  ): Promise<ArrayBuffer> {
    const file = this.centralDirectoryRecords.find(
      (r) => r.data.filename === path
    );
    if (!file) {
      throw new RemoteZipError(`File not found in remote ZIP: ${path}`);
    }

    // @ts-expect-error polyfill types
    const headers = new fetch.Headers(additionalHeaders);
    // Local file headers have variable length due to filename/path.
    // To avoid making an additional Range query, we fetch extra bytes for the header.
    // 256: path
    // 32: extra field
    // 30: other header fields
    // 100: generous buffer
    const MAX_LOCAL_FILE_HEADER_SIZE = 256 + 32 + 30 + 100;
    headers.append(
      "Range",
      `bytes=${file.data.localFileHeaderRelativeOffset}-${
        file.data.localFileHeaderRelativeOffset +
        file.data.compressedSize +
        MAX_LOCAL_FILE_HEADER_SIZE
      }`
    );

    const response = await fetch(this.url.toString(), {
      method: this.method,
      headers,
      redirect: "follow", // TODO: make this configurable
      credentials: this.credentials,
      // TODO: additional fetch options
    });
    const localFile = parseOneLocalFile(
      await response.arrayBuffer(),
      file.data.compressedSize
    );
    if (!localFile) {
      throw new RemoteZipError("cannot parse local file header in remote ZIP");
    }

    // 0 = uncompressed, 8 = deflate
    if (localFile.data.compressionMethod === 0) {
      return localFile.meta.compressedData;
    } else {
      // Try DEFLATE anyway
      const uncompressed = inflateRaw(
        new Uint8Array(localFile.meta.compressedData)
      );
      return uncompressed;
    }
  }
}

/**
 * Pointer to a remote zip file at a url. To get a concrete remote zip file, call `myPointer.populate()`.
 */
export class RemoteZipPointer {
  url: URL;
  additionalHeaders?: Headers;
  method: string;
  credentials: "include" | "omit" | "same-origin";

  constructor({
    url,
    additionalHeaders,
    method = "GET",
    credentials = "same-origin",
  }: {
    url: URL;
    additionalHeaders?: Headers;
    method?: string;
    credentials?: "include" | "omit" | "same-origin";
  }) {
    this.url = url;
    this.additionalHeaders = additionalHeaders;
    this.method = method;
    this.credentials = credentials;
  }

  public async populate(): Promise<RemoteZip> {
    const res = await fetch(this.url.toString(), {
      method: "HEAD",
      headers: this.additionalHeaders,
      redirect: "follow",
      credentials: this.credentials,
    });
    const contentLengthRaw = res.headers.get("content-length");
    if (!contentLengthRaw) {
      throw new RemoteZipError("Could not get Content-Length of URL");
    }
    const contentLength = Number.parseInt(contentLengthRaw, 10);
    const endOfCentralDirectory = await this.fetchEndOfCentralDirectory(
      contentLength
    );
    const centralDirectoryRecords = await this.fetchCentralDirectoryRecords(
      endOfCentralDirectory,
      this.additionalHeaders
    );

    return new RemoteZip({
      url: this.url,
      contentLength,
      endOfCentralDirectory,
      centralDirectoryRecords,
      method: this.method,
      credentials: this.credentials,
    });
  }

  private async fetchEndOfCentralDirectory(
    zipByteLength: number,
    additionalHeaders?: Headers
  ): Promise<EndOfCentralDirectory> {
    // EOCD has a variable length, due to the option of including a comment as the last field of the record.
    // If there’s no comment it should only be 22 bytes. Arbitrary number.
    // TODO: Fetch again if EOCD length > EOCD_MAX_BYTES
    const EOCD_MAX_BYTES = 128;
    const eocdInitialOffset = Math.max(0, zipByteLength - EOCD_MAX_BYTES);
    // @ts-expect-error polyfill types
    const eocdHeaders = new fetch.Headers(additionalHeaders);
    eocdHeaders.append("Range", `bytes=${eocdInitialOffset}-${zipByteLength}`);
    const eocdRes = await fetch(this.url.toString(), {
      method: this.method,
      headers: eocdHeaders,
      redirect: "follow",
      credentials: this.credentials,
    });
    if (eocdRes.status < 200 || eocdRes.status >= 400) {
      throw new RemoteZipError(
        `Could not fetch remote ZIP at ${this.url}: HTTP status ${eocdRes.status}`
      );
    }

    const eocdBuffer = await eocdRes.arrayBuffer();
    if (!eocdBuffer) {
      throw new RemoteZipError(
        "Could not get Range request to start looking for EOCD"
      );
    }
    const eocd = parseOneEOCD(eocdBuffer);

    // 0xffff = ZIP64
    if (!eocd) {
      throw new RemoteZipError("Could not get EOCD record of remote ZIP");
    }

    if (eocd.data.cdDisk === 0xffff) {
      throw new RemoteZipError(
        "ZIP file not supported: could not get EOCD record or ZIP64"
      );
    }

    return eocd;
  }

  private async fetchCentralDirectoryRecords(
    endOfCentralDirectory: EndOfCentralDirectory,
    additionalHeaders?: Headers
  ): Promise<CentralDirectoryRecord[]> {
    // Fetch CD
    // @ts-expect-error polyfill types
    const cdHeaders = new fetch.Headers(additionalHeaders);
    cdHeaders.append(
      "Range",
      `bytes=${endOfCentralDirectory.data.centralDirectoryByteOffset}-${
        endOfCentralDirectory.data.centralDirectoryByteOffset +
        endOfCentralDirectory.data.centralDirectoryByteSize
      }`
    );
    const cdRes = await fetch(this.url.toString(), {
      method: this.method,
      headers: cdHeaders,
      redirect: "follow",
      credentials: this.credentials,
    });
    const cdBuffer = await cdRes.arrayBuffer();
    const cd = parseAllCDs(cdBuffer);

    return cd;
  }
}

/**
 * @see https://github.com/Stuk/jszip/blob/112fcdb9953c6b9a2744afee451d73029f7cd2f8/lib/reader/DataReader.js#L105
 */
const parseZipDatetime = (zipDate: number, zipTime: number): string => {
  const day = zipDate & 0x1f;
  const month = (zipDate >> 5) & 0x0f;
  const year = ((zipDate >> 9) & 0x7f) + 1980;
  const hour = (zipTime >> 11) & 0x1f;
  const minute = (zipTime >> 5) & 0x3f;
  const second = (zipTime & 0x1f) << 1;

  const pad = (num: number): string => num.toString().padStart(2, "0");

  // ZIP doesn't have timezones, but JS parses it as UTC with `new Date`.
  // Manually construct an ISO timestamp without timezone to represent this.
  return `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(minute)}:${pad(
    second
  )}`;
};

const parseAllCDs = (buffer: ArrayBufferLike): CentralDirectoryRecord[] => {
  const cds: CentralDirectoryRecord[] = [];
  const view = new DataView(buffer);

  // Need >= 4 bytes to check for signature
  for (let i = 0; i <= buffer.byteLength - 4; i += 1) {
    if (view.getUint32(i) === SIG_CD) {
      const cd = parseOneCD(buffer.slice(i));
      if (cd) {
        cds.push(cd);
        i += cd.meta.length - 1;
        continue;
      }
    } else if (view.getUint32(i) === SIG_EOCD) {
      break;
    }
  }

  return cds;
};

const parseOneCD = (buffer: ArrayBufferLike): CentralDirectoryRecord | null => {
  const MIN_CD_LENGTH = 46;

  const view = new DataView(buffer);
  const decoder = new TextDecoder();

  // Seek to start of central directory
  for (let i = 0; i < buffer.byteLength - MIN_CD_LENGTH; i += 1) {
    if (view.getInt32(i) === SIG_CD) {
      const filenameLength = view.getUint16(i + 28, true); // n
      const extraFieldLength = view.getUint16(i + 30, true); // m
      const fileCommentLength = view.getUint16(i + 32, true); // k

      return {
        meta: {
          length: 46 + filenameLength + extraFieldLength + fileCommentLength,
        },
        data: {
          signature: buffer.slice(i, i + 4),
          versionMadeBy: view.getUint16(i + 4, true),
          versionToExtract: view.getUint16(i + 6, true),
          generalPurposeBitFlag: view.getUint16(i + 8, true),
          compressionMethod: view.getUint16(i + 10, true),
          lastModifiedTime: view.getUint16(i + 12, true),
          lastModifiedDate: view.getUint16(i + 14, true),
          crc32: view.getUint32(i + 16, true),
          compressedSize: view.getUint32(i + 20, true),
          uncompressedSize: view.getUint32(i + 24, true),
          filenameLength,
          extraFieldLength,
          fileCommentLength,
          startingDiskNumber: view.getUint16(i + 34, true),
          internalFileAttributes: view.getUint16(i + 36, true),
          externalFileAttributes: view.getUint32(i + 38, true),
          localFileHeaderRelativeOffset: view.getUint32(i + 42, true),
          filename: decoder.decode(
            buffer.slice(i + 46, i + 46 + filenameLength)
          ),
          extraField: buffer.slice(
            i + 46 + filenameLength,
            i + 46 + filenameLength + extraFieldLength
          ),
          fileComment: decoder.decode(
            buffer.slice(
              i + 46 + filenameLength + extraFieldLength,
              i + 46 + filenameLength + extraFieldLength + fileCommentLength
            )
          ),
        },
      };
    }
  }

  return null;
};

const parseOneEOCD = (
  buffer: ArrayBufferLike
): EndOfCentralDirectory | null => {
  const MIN_EOCD_LENGTH = 22;

  const view = new DataView(buffer);
  const decoder = new TextDecoder();

  // Seek to end of central directory record
  for (let i = 0; i <= buffer.byteLength - MIN_EOCD_LENGTH; i += 1) {
    if (view.getUint32(i) === SIG_EOCD) {
      const commentLength = view.getUint16(i + 20, false);

      // https://en.wikipedia.org/wiki/ZIP_(file_format)#End_of_central_directory_record_(EOCD)
      return {
        meta: {},
        data: {
          signature: buffer.slice(i, i + 4),
          diskNumber: view.getUint16(i + 4, true),
          cdDisk: view.getUint16(i + 6, true),
          centralDirectoryDiskNumber: view.getUint16(i + 8, true),
          centralDirectoryRecordCount: view.getUint16(i + 10, true),
          centralDirectoryByteSize: view.getInt32(i + 12, true),
          centralDirectoryByteOffset: view.getInt32(i + 16, true),
          commentLength: commentLength,
          comment: decoder.decode(buffer.slice(i + 22, i + 22 + commentLength)),
        },
      };
    }
  }

  return null;
};

const parseOneLocalFile = (
  buffer: ArrayBufferLike,
  /** Sometimes, the local header does not have the compressed size and a data descriptor is used after the compressed data.
   * If provided, will be used if the local header indicates a data descriptor block.
   * It is used to find the correct offset for the data descriptor. */
  compressedSizeOverride = 0
): LocalFileHeader | null => {
  const MIN_LOCAL_FILE_LENGTH = 30;

  const view = new DataView(buffer);
  const decoder = new TextDecoder();

  // Seek to first local file
  for (let i = 0; i <= buffer.byteLength - MIN_LOCAL_FILE_LENGTH; i += 1) {
    if (view.getUint32(i) === SIG_LOCAL_FILE_HEADER) {
      const filenameLength = view.getUint16(i + 26, true); // n
      const extraFieldLength = view.getUint16(i + 28, true); // m

      const bitflags = view.getUint16(i + 6, true);
      const hasDataDescriptor = Boolean((bitflags >> 3) & 1);

      const headerEndOffset = i + 30 + filenameLength + extraFieldLength;
      const regularCompressedSize = view.getUint32(i + 18, true);

      const hasOptionalSignature =
        view.getUint32(headerEndOffset + compressedSizeOverride) ===
        SIG_DATA_DESCRIPTOR;
      const optionalSignatureOffset = hasOptionalSignature ? 4 : 0;

      return {
        meta: {
          dataDescriptor: hasDataDescriptor
            ? {
                optionalSignature: hasOptionalSignature
                  ? buffer.slice(
                      headerEndOffset + compressedSizeOverride,
                      headerEndOffset +
                        compressedSizeOverride +
                        optionalSignatureOffset
                    )
                  : undefined,
                crc32: view.getUint32(
                  headerEndOffset +
                    compressedSizeOverride +
                    optionalSignatureOffset,
                  true
                ),
                compressedSize: view.getUint32(
                  headerEndOffset +
                    compressedSizeOverride +
                    optionalSignatureOffset +
                    4,
                  true
                ),
                uncompressedSize: view.getUint32(
                  headerEndOffset +
                    compressedSizeOverride +
                    optionalSignatureOffset +
                    8,
                  true
                ),
              }
            : undefined,
          compressedData: hasDataDescriptor
            ? buffer.slice(
                headerEndOffset,
                headerEndOffset + compressedSizeOverride
              )
            : buffer.slice(
                headerEndOffset,
                headerEndOffset + regularCompressedSize
              ),
        },
        data: {
          signature: buffer.slice(i, i + 4),
          versionToExtract: view.getUint16(i + 4, true),
          generalPurposeBitFlag: view.getUint16(i + 6, true),
          compressionMethod: view.getUint16(i + 8, true),
          lastModifiedTime: view.getUint16(i + 10, true),
          lastModifiedDate: view.getUint16(i + 12, true),
          crc32: view.getUint32(i + 14, true),
          compressedSize: regularCompressedSize,
          uncompressedSize: view.getUint32(i + 22, true),
          filenameLength,
          extraFieldLength,
          filename: decoder.decode(
            buffer.slice(i + 30, i + 30 + filenameLength)
          ),
          extraField: buffer.slice(
            i + 30 + filenameLength,
            i + 30 + filenameLength + extraFieldLength
          ),
        },
      };
    }
  }

  return null;
};
