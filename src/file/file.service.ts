import { Injectable, Logger } from '@nestjs/common';
import { Readable, Stream } from 'stream';
import * as fs from 'fs';
import * as path from 'path';
import { CloudProvidersMetaData } from './cloud.providers.metadata';
import { R_OK } from 'constants';
import { URL } from 'url';

@Injectable()
export class FileService {
  private readonly logger = new Logger(FileService.name);
  private cloudProviders = new CloudProvidersMetaData();

  async getFile(file: string): Promise<Stream> {
    this.logger.log(`Reading file: ${file}`);

    // Validate the file path to prevent directory traversal
    if (file.includes('..')) {
      throw new Error('Invalid file path');
    }

    // Ensure the file path is within a specific directory
    const baseDir = path.resolve(process.cwd(), 'allowed_directory');
    const resolvedPath = path.resolve(baseDir, file);
    if (!resolvedPath.startsWith(baseDir)) {
      throw new Error('Access to this file path is not allowed');
    }

    if (file.startsWith('/')) {
      await fs.promises.access(file, R_OK);

      return fs.createReadStream(file);
    } else if (file.startsWith('http')) {
      // Validate URL
      let url;
      try {
        url = new URL(file);
      } catch (err) {
        throw new Error('Invalid URL');
      }

      // Check against allowed hosts
      const allowedHosts = [
        'metadata.google.internal',
        '169.254.169.254'
      ];

      // Fix: Ensure the URL is not pointing to internal IPs or metadata services
      const internalIpRegex = /^(127\.0\.0\.1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/;
      if (internalIpRegex.test(url.hostname) || allowedHosts.includes(url.hostname)) {
        throw new Error('Host not allowed');
      }

      // Allow only specific protocols
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new Error('Invalid protocol');
      }

      const content = await this.cloudProviders.get(file);

      if (content) {
        return Readable.from(content);
      } else {
        throw new Error(`no such file or directory, access '${file}'`);
      }
    } else {
      await fs.promises.access(resolvedPath, R_OK);

      return fs.createReadStream(resolvedPath);
    }
  }

  async deleteFile(file: string): Promise<boolean> {
    if (file.startsWith('/')) {
      throw new Error('cannot delete file from this location');
    } else if (file.startsWith('http')) {
      throw new Error('cannot delete file from this location');
    } else {
      file = path.resolve(process.cwd(), file);
      await fs.promises.unlink(file);
      return true;
    }
  }
}
