import { CleanMailAnalyzer as RuntimeCleanMailAnalyzer, isPublicIp } from './analyzer.js';
import { CleanMailDetector } from './detector.js';
import { probeSmtp } from './smtp.js';

export class CleanMailAnalyzer extends RuntimeCleanMailAnalyzer {
  constructor(detector = new CleanMailDetector(), options = {}) {
    super(detector, {
      ...options,
      smtpProbe: options.smtpProbe || probeSmtp,
    });
  }
}

export { isPublicIp };
