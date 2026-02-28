/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import * as forge from 'node-forge';
import { Shield, FileCode, Key, Download, Info, AlertCircle, CheckCircle2, Lock, FileUp, FileDown, Eye, EyeOff, Calendar, User, Building, Hash, Clock, Rocket, Heart, Coffee, Smartphone, Copy, X, QrCode } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

type Mode = 'create' | 'extract' | 'inspect';

interface CertInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validity: {
    notBefore: Date;
    notAfter: Date;
    isExpired: boolean;
  };
  serialNumber: string;
  fingerprint: string;
}

export default function App() {
  const [mode, setMode] = useState<Mode>('create');
  
  // Create state
  const [crtFile, setCrtFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [caFile, setCaFile] = useState<File | null>(null);
  
  // Extract/Inspect state
  const [pfxFile, setPfxFile] = useState<File | null>(null);
  const [inspectCrtFile, setInspectCrtFile] = useState<File | null>(null);
  const [showYapeModal, setShowYapeModal] = useState(false);
  const [copied, setCopied] = useState(false);
  
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [inspectedInfo, setInspectedInfo] = useState<CertInfo | null>(null);

  const crtInputRef = useRef<HTMLInputElement>(null);
  const keyInputRef = useRef<HTMLInputElement>(null);
  const caInputRef = useRef<HTMLInputElement>(null);
  const pfxInputRef = useRef<HTMLInputElement>(null);
  const inspectCrtInputRef = useRef<HTMLInputElement>(null);

  const readFileAsText = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target?.result as string);
      reader.onerror = (e) => reject(new Error('Error reading file'));
      reader.readAsText(file);
    });
  };

  const readFileAsBinary = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target?.result as string);
      reader.onerror = (e) => reject(new Error('Error reading file'));
      reader.readAsBinaryString(file);
    });
  };

  const readFileAsArrayBuffer = (file: File): Promise<ArrayBuffer> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target?.result as ArrayBuffer);
      reader.onerror = (e) => reject(new Error('Error reading file'));
      reader.readAsArrayBuffer(file);
    });
  };

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const parseCertInfo = (cert: forge.pki.Certificate): CertInfo => {
    const subject: Record<string, string> = {};
    cert.subject.attributes.forEach(attr => {
      if (attr.shortName) subject[attr.shortName] = attr.value as string;
    });

    const issuer: Record<string, string> = {};
    cert.issuer.attributes.forEach(attr => {
      if (attr.shortName) issuer[attr.shortName] = attr.value as string;
    });

    const now = new Date();
    const notAfter = cert.validity.notAfter;
    
    // Fingerprint
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha256.create();
    md.update(der);
    const fingerprint = md.digest().toHex().match(/.{1,2}/g)?.join(':').toUpperCase() || '';

    return {
      subject,
      issuer,
      validity: {
        notBefore: cert.validity.notBefore,
        notAfter: cert.validity.notAfter,
        isExpired: now > notAfter
      },
      serialNumber: cert.serialNumber,
      fingerprint
    };
  };

  const handleCreatePFX = async () => {
    if (!crtFile || !keyFile) {
      setError('Por favor, selecciona al menos el certificado (.crt) y la llave privada (.key).');
      return;
    }

    setIsProcessing(true);
    setError(null);
    setSuccess(false);

    try {
      const crtPem = await readFileAsText(crtFile);
      const keyPem = await readFileAsText(keyFile);
      let caPem = '';
      if (caFile) {
        caPem = await readFileAsText(caFile);
      }

      const cert = forge.pki.certificateFromPem(crtPem);
      let privateKey;
      try {
        privateKey = forge.pki.privateKeyFromPem(keyPem);
      } catch (e) {
        throw new Error('No se pudo procesar la llave privada. Asegúrate de que sea un formato PEM válido.');
      }

      const caCerts: forge.pki.Certificate[] = [];
      if (caPem) {
        const caPems = caPem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
        if (caPems) {
          caPems.forEach(pem => {
            caCerts.push(forge.pki.certificateFromPem(pem));
          });
        }
      }

      const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
        privateKey,
        [cert, ...caCerts],
        password,
        { algorithm: 'aes256' }
      );

      const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
      const p12Uint8 = new Uint8Array(p12Der.length);
      for (let i = 0; i < p12Der.length; i++) {
        p12Uint8[i] = p12Der.charCodeAt(i);
      }

      const blob = new Blob([p12Uint8], { type: 'application/x-pkcs12' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = crtFile.name.replace(/\.[^/.]+$/, "") + ".pfx";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setSuccess(true);
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Error durante la creación. Verifica los archivos.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleExtractPFX = async () => {
    if (!pfxFile) {
      setError('Por favor, selecciona un archivo .pfx o .p12.');
      return;
    }

    setIsProcessing(true);
    setError(null);
    setSuccess(false);

    try {
      const p12Buffer = await readFileAsArrayBuffer(pfxFile);
      const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(p12Buffer));
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

      const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });

      if (keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.length) {
        const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
        const keyPem = forge.pki.privateKeyToPem(keyBag.key!);
        downloadFile(keyPem, pfxFile.name.replace(/\.[^/.]+$/, "") + ".key", 'text/plain');
      } else {
        const plainKeyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
        if (plainKeyBags[forge.pki.oids.keyBag]?.length) {
          const keyBag = plainKeyBags[forge.pki.oids.keyBag]![0];
          const keyPem = forge.pki.privateKeyToPem(keyBag.key!);
          downloadFile(keyPem, pfxFile.name.replace(/\.[^/.]+$/, "") + ".key", 'text/plain');
        }
      }

      if (certBags[forge.pki.oids.certBag]?.length) {
        let fullCertPem = '';
        certBags[forge.pki.oids.certBag]!.forEach(bag => {
          fullCertPem += forge.pki.certificateToPem(bag.cert!) + '\n';
        });
        downloadFile(fullCertPem, pfxFile.name.replace(/\.[^/.]+$/, "") + ".crt", 'text/plain');
      }

      setSuccess(true);
    } catch (err: any) {
      console.error(err);
      if (err.message?.includes('MAC could not be verified')) {
        setError('Contraseña incorrecta. No se pudo verificar la integridad del archivo PFX.');
      } else {
        setError('Error al extraer. Verifica que el archivo sea un PFX válido y la contraseña sea correcta.');
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const handleInspect = async () => {
    setError(null);
    setInspectedInfo(null);
    setIsProcessing(true);

    try {
      if (pfxFile) {
        const p12Buffer = await readFileAsArrayBuffer(pfxFile);
        const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(p12Buffer));
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
        const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
        
        if (certBags[forge.pki.oids.certBag]?.length) {
          const cert = certBags[forge.pki.oids.certBag]![0].cert!;
          setInspectedInfo(parseCertInfo(cert));
          setSuccess(true);
        } else {
          throw new Error('No se encontraron certificados en el archivo PFX.');
        }
      } else if (inspectCrtFile) {
        const crtPem = await readFileAsText(inspectCrtFile);
        const cert = forge.pki.certificateFromPem(crtPem);
        setInspectedInfo(parseCertInfo(cert));
        setSuccess(true);
      } else {
        setError('Selecciona un archivo para inspeccionar.');
      }
    } catch (err: any) {
      console.error(err);
      if (err.message?.includes('MAC could not be verified')) {
        setError('Contraseña incorrecta para este archivo PFX.');
      } else {
        setError('Error al inspeccionar. Verifica el archivo y la contraseña.');
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const resetState = () => {
    setError(null);
    setSuccess(false);
    setPassword('');
    setInspectedInfo(null);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#f8fafc] text-navy font-jakarta p-4 md:p-8 relative overflow-hidden">
      {/* Background Blobs */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-brand-200/20 rounded-full blur-3xl animate-blob" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-accent/5 rounded-full blur-3xl animate-blob [animation-delay:2s]" />
      <div className="absolute top-[40%] right-[20%] w-[30%] h-[30%] bg-coral/5 rounded-full blur-3xl animate-blob [animation-delay:4s]" />

      <div className="max-w-4xl mx-auto relative z-10">
        {/* Header */}
        <header className="mb-8 border-b border-brand-100 pb-6 animate-fade-in-up">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="relative w-12 h-12 flex items-center justify-center">
                {/* Custom Rocket Logo mimicking the user's image */}
                <div className="absolute inset-0 bg-brand-500 rounded-xl rotate-3 opacity-20 animate-pulse" />
                <div className="relative p-2.5 bg-white rounded-xl shadow-xl shadow-brand-500/10 border border-brand-100 flex items-center justify-center">
                  <div className="relative">
                    <Rocket className="w-7 h-7 text-brand-500 fill-brand-500/10" />
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-2 h-2 bg-accent rounded-full shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
                  </div>
                </div>
              </div>
              <h1 className="text-3xl font-extrabold tracking-tight font-sora bg-clip-text text-transparent bg-gradient-to-r from-navy via-brand-600 to-accent">gaortools</h1>
            </div>
            
            {/* Mode Switcher */}
            <div className="flex bg-white/50 backdrop-blur-md border border-brand-100 p-1 rounded-2xl shadow-sm overflow-x-auto">
              <button 
                onClick={() => { setMode('create'); resetState(); }}
                className={`px-4 py-2 text-xs font-bold uppercase tracking-widest transition-all rounded-xl flex items-center gap-2 whitespace-nowrap font-sora ${mode === 'create' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/30' : 'text-brand-600 hover:bg-brand-50'}`}
              >
                <FileUp className="w-3 h-3" /> Crear
              </button>
              <button 
                onClick={() => { setMode('extract'); resetState(); }}
                className={`px-4 py-2 text-xs font-bold uppercase tracking-widest transition-all rounded-xl flex items-center gap-2 whitespace-nowrap font-sora ${mode === 'extract' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/30' : 'text-brand-600 hover:bg-brand-50'}`}
              >
                <FileDown className="w-3 h-3" /> Extraer
              </button>
              <button 
                onClick={() => { setMode('inspect'); resetState(); }}
                className={`px-4 py-2 text-xs font-bold uppercase tracking-widest transition-all rounded-xl flex items-center gap-2 whitespace-nowrap font-sora ${mode === 'inspect' ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/30' : 'text-brand-600 hover:bg-brand-50'}`}
              >
                <Eye className="w-3 h-3" /> Inspeccionar
              </button>
            </div>
          </div>
          <p className="mt-4 text-navy-light font-jakarta font-medium text-lg opacity-80">
            {mode === 'create' && 'Convierte tus certificados PEM (.crt, .key) a formato PKCS#12 (.pfx).'}
            {mode === 'extract' && 'Extrae el certificado y la llave de un archivo PKCS#12 (.pfx, .p12).'}
            {mode === 'inspect' && 'Verifica la validez y detalles de un certificado o archivo PFX.'}
          </p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Controls */}
          <div className="lg:col-span-2 space-y-6">
            <div className="glass-card p-6 rounded-3xl animate-fade-in-up [animation-delay:0.2s]">
              <h2 className="text-[10px] font-sora font-bold uppercase tracking-[0.2em] text-brand-500 mb-6 flex items-center gap-2">
                <span className="w-2 h-2 bg-accent rounded-full animate-pulse" />
                {mode === 'create' ? 'Configuración de Archivos PEM' : mode === 'extract' ? 'Archivo PFX / P12' : 'Seleccionar Archivo'}
              </h2>
              
              <div className="space-y-4">
                {mode === 'create' && (
                  <>
                    <div className="group">
                      <label className="block text-sm font-bold mb-2 flex items-center gap-2 font-sora text-navy">
                        <FileCode className="w-4 h-4 text-brand-500" /> Certificado (.crt / .pem)
                      </label>
                      <div 
                        onClick={() => crtInputRef.current?.click()}
                        className={`border-2 border-dashed border-brand-100 p-4 rounded-2xl cursor-pointer transition-all hover:border-brand-300 hover:bg-brand-50/50 flex items-center justify-between ${crtFile ? 'bg-accent/5 border-accent/30' : ''}`}
                      >
                        <span className="text-sm truncate max-w-[200px] font-jakarta text-navy-light">
                          {crtFile ? crtFile.name : 'Seleccionar archivo...'}
                        </span>
                        <input 
                          type="file" 
                          ref={crtInputRef} 
                          className="hidden" 
                          accept=".crt,.pem,.cer"
                          onChange={(e) => setCrtFile(e.target.files?.[0] || null)}
                        />
                        {crtFile && <CheckCircle2 className="w-4 h-4 text-accent" />}
                      </div>
                    </div>

                    <div className="group">
                      <label className="block text-sm font-bold mb-2 flex items-center gap-2 font-sora text-navy">
                        <Key className="w-4 h-4 text-brand-500" /> Llave Privada (.key)
                      </label>
                      <div 
                        onClick={() => keyInputRef.current?.click()}
                        className={`border-2 border-dashed border-brand-100 p-4 rounded-2xl cursor-pointer transition-all hover:border-brand-300 hover:bg-brand-50/50 flex items-center justify-between ${keyFile ? 'bg-accent/5 border-accent/30' : ''}`}
                      >
                        <span className="text-sm truncate max-w-[200px] font-jakarta text-navy-light">
                          {keyFile ? keyFile.name : 'Seleccionar archivo...'}
                        </span>
                        <input 
                          type="file" 
                          ref={keyInputRef} 
                          className="hidden" 
                          accept=".key,.pem"
                          onChange={(e) => setKeyFile(e.target.files?.[0] || null)}
                        />
                        {keyFile && <CheckCircle2 className="w-4 h-4 text-accent" />}
                      </div>
                    </div>
                  </>
                )}

                {mode === 'extract' && (
                  <div className="group">
                    <label className="block text-sm font-bold mb-2 flex items-center gap-2 font-sora text-navy">
                      <Shield className="w-4 h-4 text-brand-500" /> Archivo PFX / P12
                    </label>
                    <div 
                      onClick={() => pfxInputRef.current?.click()}
                      className={`border-2 border-dashed border-brand-100 p-4 rounded-2xl cursor-pointer transition-all hover:border-brand-300 hover:bg-brand-50/50 flex items-center justify-between ${pfxFile ? 'bg-accent/5 border-accent/30' : ''}`}
                    >
                      <span className="text-sm truncate max-w-[200px] font-jakarta text-navy-light">
                        {pfxFile ? pfxFile.name : 'Seleccionar archivo .pfx o .p12...'}
                      </span>
                      <input 
                        type="file" 
                        ref={pfxInputRef} 
                        className="hidden" 
                        accept=".pfx,.p12"
                        onChange={(e) => setPfxFile(e.target.files?.[0] || null)}
                      />
                      {pfxFile && <CheckCircle2 className="w-4 h-4 text-accent" />}
                    </div>
                  </div>
                )}

                {mode === 'inspect' && (
                  <div className="space-y-4">
                    <div className="group">
                      <label className="block text-sm font-bold mb-2 flex items-center gap-2 font-sora text-navy">
                        <FileCode className="w-4 h-4 text-brand-500" /> Certificado (.crt) o PFX (.pfx)
                      </label>
                      <div 
                        onClick={() => inspectCrtInputRef.current?.click()}
                        className={`border-2 border-dashed border-brand-100 p-4 rounded-2xl cursor-pointer transition-all hover:border-brand-300 hover:bg-brand-50/50 flex items-center justify-between ${inspectCrtFile || pfxFile ? 'bg-accent/5 border-accent/30' : ''}`}
                      >
                        <span className="text-sm truncate max-w-[200px] font-jakarta text-navy-light">
                          {inspectCrtFile ? inspectCrtFile.name : pfxFile ? pfxFile.name : 'Seleccionar archivo...'}
                        </span>
                        <input 
                          type="file" 
                          ref={inspectCrtInputRef} 
                          className="hidden" 
                          accept=".crt,.pem,.cer,.pfx,.p12"
                          onChange={(e) => {
                            const file = e.target.files?.[0] || null;
                            if (file?.name.endsWith('.pfx') || file?.name.endsWith('.p12')) {
                              setPfxFile(file);
                              setInspectCrtFile(null);
                            } else {
                              setInspectCrtFile(file);
                              setPfxFile(null);
                            }
                          }}
                        />
                        {(inspectCrtFile || pfxFile) && <CheckCircle2 className="w-4 h-4 text-accent" />}
                      </div>
                    </div>
                  </div>
                )}

                {/* Password Input (Only for PFX related actions) */}
                {(mode === 'extract' || (mode === 'inspect' && pfxFile) || mode === 'create') && (
                  <div className="pt-4">
                    <label className="block text-sm font-bold mb-2 flex items-center gap-2 font-sora text-navy">
                      <Lock className="w-4 h-4 text-brand-500" /> Contraseña
                    </label>
                    <div className="relative">
                      <input 
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Ingresa la contraseña"
                        className="w-full p-4 pr-12 bg-white border border-brand-100 rounded-2xl focus:outline-none focus:ring-4 focus:ring-brand-500/10 focus:border-brand-500 transition-all font-jakarta text-sm"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-brand-500 transition-colors"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className="mt-8">
                <button
                  onClick={mode === 'create' ? handleCreatePFX : mode === 'extract' ? handleExtractPFX : handleInspect}
                  disabled={isProcessing || (mode === 'create' ? (!crtFile || !keyFile) : mode === 'extract' ? !pfxFile : (!pfxFile && !inspectCrtFile))}
                  className={`w-full py-4 bg-navy text-white font-bold uppercase tracking-widest rounded-2xl flex items-center justify-center gap-2 transition-all active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed hover:bg-navy-light shadow-xl shadow-navy/20 font-sora`}
                >
                  {isProcessing ? (
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <>
                      {mode === 'inspect' ? <Eye className="w-5 h-5" /> : <Download className="w-5 h-5" />}
                      {mode === 'create' ? 'Generar .pfx' : mode === 'extract' ? 'Extraer Archivos' : 'Inspeccionar'}
                    </>
                  )}
                </button>
              </div>

              <AnimatePresence>
                {error && (
                  <motion.div 
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    className="mt-4 p-4 bg-red-50 border border-red-100 rounded-2xl text-red-600 text-sm flex items-start gap-3"
                  >
                    <AlertCircle className="w-5 h-5 shrink-0" />
                    <p className="font-medium">{error}</p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Inspected Info Display */}
            <AnimatePresence>
              {inspectedInfo && (
                <motion.div 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="glass-card p-6 rounded-3xl space-y-6"
                >
                  <div className="flex items-center justify-between border-b border-brand-50 pb-4">
                    <h3 className="font-extrabold uppercase tracking-tight flex items-center gap-2 font-sora text-navy">
                      <Info className="w-5 h-5 text-brand-500" /> Detalles del Certificado
                    </h3>
                    <div className={`px-4 py-1.5 text-[10px] font-bold uppercase tracking-widest rounded-full font-sora ${inspectedInfo.validity.isExpired ? 'bg-red-100 text-red-600' : 'bg-accent/10 text-accent'}`}>
                      {inspectedInfo.validity.isExpired ? 'Expirado' : 'Válido'}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Subject */}
                    <div className="space-y-3">
                      <h4 className="text-[10px] font-sora font-bold uppercase tracking-widest text-slate-400 flex items-center gap-1">
                        <User className="w-3 h-3 text-coral" /> Sujeto (Subject)
                      </h4>
                      <div className="space-y-1">
                        <p className="text-sm font-bold font-sora text-navy">{inspectedInfo.subject.CN || 'N/A'}</p>
                        <p className="text-xs font-medium text-navy-light font-jakarta">{inspectedInfo.subject.O || inspectedInfo.subject.OU || 'Sin Organización'}</p>
                        <p className="text-[10px] text-slate-400 font-jakarta">{inspectedInfo.subject.L}, {inspectedInfo.subject.ST}, {inspectedInfo.subject.C}</p>
                      </div>
                    </div>

                    {/* Issuer */}
                    <div className="space-y-3">
                      <h4 className="text-[10px] font-sora font-bold uppercase tracking-widest text-slate-400 flex items-center gap-1">
                        <Building className="w-3 h-3 text-brand-500" /> Emisor (Issuer)
                      </h4>
                      <div className="space-y-1">
                        <p className="text-sm font-bold font-sora text-navy">{inspectedInfo.issuer.CN || 'N/A'}</p>
                        <p className="text-xs font-medium text-navy-light font-jakarta">{inspectedInfo.issuer.O || 'N/A'}</p>
                      </div>
                    </div>

                    {/* Dates */}
                    <div className="space-y-3">
                      <h4 className="text-[10px] font-sora font-bold uppercase tracking-widest text-slate-400 flex items-center gap-1">
                        <Calendar className="w-3 h-3 text-accent" /> Validez
                      </h4>
                      <div className="space-y-2 text-xs font-jakarta">
                        <div className="flex justify-between items-center p-2 bg-brand-50/50 rounded-xl">
                          <span className="text-navy-light font-medium">Desde:</span>
                          <span className="font-bold text-brand-600">{inspectedInfo.validity.notBefore.toLocaleDateString()}</span>
                        </div>
                        <div className="flex justify-between items-center p-2 bg-brand-50/50 rounded-xl">
                          <span className="text-navy-light font-medium">Hasta:</span>
                          <span className="font-bold text-brand-600">{inspectedInfo.validity.notAfter.toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>

                    {/* Meta */}
                    <div className="space-y-3">
                      <h4 className="text-[10px] font-sora font-bold uppercase tracking-widest text-slate-400 flex items-center gap-1">
                        <Hash className="w-3 h-3 text-navy" /> Metadatos
                      </h4>
                      <div className="space-y-1 text-xs font-jakarta">
                        <div className="flex justify-between gap-4 items-center p-2 bg-brand-50/50 rounded-xl">
                          <span className="text-navy-light font-medium">Serial:</span>
                          <span className="font-bold text-brand-600 truncate max-w-[120px]">{inspectedInfo.serialNumber}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-brand-50">
                    <h4 className="text-[10px] font-sora font-bold uppercase tracking-widest text-slate-400 mb-2">Fingerprint (SHA-256)</h4>
                    <code className="block bg-slate-50 p-4 rounded-2xl text-[10px] font-jakarta font-bold text-brand-700 break-all leading-relaxed border border-brand-100">
                      {inspectedInfo.fingerprint}
                    </code>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Sidebar / Info */}
          <div className="space-y-6">
            <div className="bg-navy text-white p-6 rounded-3xl shadow-2xl shadow-navy/20 animate-fade-in-up [animation-delay:0.4s]">
              <h2 className="text-[10px] font-sora font-bold uppercase tracking-widest text-brand-200 mb-4 flex items-center gap-2">
                <Clock className="w-4 h-4 text-coral" /> Verificación
              </h2>
              <div className="space-y-4 text-sm font-jakarta leading-relaxed opacity-90">
                <p>
                  Para verificar si un PFX está bien creado, intenta abrirlo en la pestaña <strong>Inspeccionar</strong>. Si la contraseña es correcta y el archivo es válido, verás los detalles del certificado.
                </p>
                <p>
                  También puedes inspeccionar archivos <strong>.crt</strong> directamente para ver su fecha de expiración y emisor.
                </p>
              </div>
            </div>

            <div className="glass-card p-6 rounded-3xl animate-fade-in-up [animation-delay:0.6s]">
              <h2 className="text-[10px] font-sora font-bold uppercase tracking-widest text-slate-400 mb-4">Seguridad Local</h2>
              <p className="text-xs text-navy-light leading-relaxed font-jakarta font-medium">
                Esta herramienta no guarda logs ni archivos. Al cerrar la pestaña, toda la información procesada desaparece de la memoria de tu navegador.
              </p>
            </div>
          </div>
        </div>

        {/* Donation Section */}
        <div className="mt-12 p-6 bg-white rounded-3xl border border-brand-100 shadow-sm animate-fade-in-up [animation-delay:0.7s] flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-brand-50 rounded-2xl flex items-center justify-center">
              <Heart className="w-6 h-6 text-brand-600 fill-brand-600/10" />
            </div>
            <div>
              <h3 className="font-sora font-bold text-navy">¿Te fue útil la herramienta?</h3>
              <p className="text-sm text-navy-light/70 font-jakarta">Considera apoyar el mantenimiento de este proyecto gratuito.</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setShowYapeModal(true)}
              className="flex items-center gap-2 px-6 py-3 bg-[#742284] text-white rounded-2xl font-bold hover:bg-[#5d1b6a] transition-all shadow-lg shadow-purple-500/20 group"
            >
              <Smartphone className="w-4 h-4 group-hover:scale-110 transition-transform" />
              <span>Yape (Perú)</span>
            </button>
            <a 
              href="https://www.paypal.me/gaorsystemperu" 
              target="_blank" 
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-6 py-3 bg-[#0070ba] text-white rounded-2xl font-bold hover:bg-[#005ea6] transition-all shadow-lg shadow-blue-500/20 group"
            >
              <Coffee className="w-4 h-4 group-hover:rotate-12 transition-transform" />
              <span>Donar con PayPal</span>
            </a>
          </div>
        </div>

        <footer className="mt-12 pt-8 border-t border-brand-100 flex flex-col items-center gap-4 animate-fade-in-up [animation-delay:0.8s]">
          <div className="text-[10px] uppercase tracking-[0.3em] font-sora font-bold text-slate-300">
            gaortools • Procesamiento Local
          </div>
          <div className="flex items-center gap-2 text-xs font-jakarta font-semibold text-navy-light/60">
            <span>desarrollado por</span>
            <a 
              href="https://gaorsystem.vercel.app/" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-brand-600 hover:text-brand-500 transition-colors flex items-center gap-1.5 group"
            >
              <span className="font-bold">gaorsystem peru</span>
              <div className="w-1.5 h-1.5 bg-accent rounded-full group-hover:scale-125 transition-transform" />
            </a>
          </div>
        </footer>
      </div>

      {/* Yape Modal */}
      <AnimatePresence>
        {showYapeModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-navy/40 backdrop-blur-sm">
            <motion.div 
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
              className="bg-white rounded-[2.5rem] p-8 max-w-sm w-full shadow-2xl relative overflow-hidden"
            >
              <div className="absolute top-0 left-0 w-full h-2 bg-[#742284]" />
              
              <button 
                onClick={() => setShowYapeModal(false)}
                className="absolute top-4 right-4 p-2 hover:bg-slate-100 rounded-full transition-colors"
              >
                <X className="w-5 h-5 text-slate-400" />
              </button>

              <div className="text-center space-y-6">
                <div className="flex justify-center">
                  <div className="relative group">
                    <div className="w-48 h-48 bg-white rounded-3xl border-2 border-[#742284]/20 p-2 shadow-inner flex items-center justify-center overflow-hidden">
                      <img 
                        src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=975615244" 
                        alt="Yape QR"
                        className="w-full h-full object-contain"
                        referrerPolicy="no-referrer"
                      />
                    </div>
                    <div className="absolute -bottom-2 -right-2 w-10 h-10 bg-[#742284] rounded-2xl flex items-center justify-center shadow-lg border-4 border-white">
                      <Smartphone className="w-5 h-5 text-white" />
                    </div>
                  </div>
                </div>

                <div>
                  <h2 className="text-2xl font-sora font-bold text-navy">Donar con Yape</h2>
                  <p className="text-slate-500 mt-2">Escanea el QR o usa el número</p>
                </div>

                <div className="bg-slate-50 p-6 rounded-3xl border border-slate-100 space-y-4">
                  <div className="flex flex-col items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-widest text-slate-400">Número de celular</span>
                    <div className="flex items-center gap-3">
                      <span className="text-2xl font-mono font-bold text-[#742284]">975 615 244</span>
                      <button 
                        onClick={() => copyToClipboard('975615244')}
                        className={`p-2 rounded-xl transition-all ${copied ? 'bg-green-500 text-white' : 'bg-white text-slate-400 hover:text-[#742284] shadow-sm'}`}
                      >
                        {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  
                  <div className="pt-4 border-t border-slate-200">
                    <p className="text-sm font-medium text-navy">Luis Atilio Garcia Munoz</p>
                  </div>
                </div>

                <p className="text-xs text-slate-400 italic">
                  ¡Muchas gracias por tu apoyo!
                </p>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
