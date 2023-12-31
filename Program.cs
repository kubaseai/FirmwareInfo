using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.Security.Extensions;

/** FirmwareInfo (C) 2023 Jakub Jozwicki */

// https://sam4k.com/linternals-the-modern-boot-process-part-1/
// https://medium.com/@allypetitt/digging-into-the-linux-secure-boot-process-9631a70b158b

namespace FirmwareInfo
{
	[StructLayout(LayoutKind.Sequential)]
    class HWProfile {
		public Int32 dwDockInfo;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 39)]
		public string szHwProfileGuid;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
		public string szHwProfileName;
    }

	public class AdjPriv {
  		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  		internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
   
  		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  		internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
 
  		[DllImport("advapi32.dll", SetLastError = true)]
  		internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern IntPtr GetCurrentProcess();
 
 		 [StructLayout(LayoutKind.Sequential, Pack = 1)]
 		 internal struct TokPriv1Luid {
   			public int Count;
			public long Luid;
			public int Attr;
		}
   
		internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
		internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
		internal const int TOKEN_QUERY = 0x00000008;
		internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
 
		public static bool SetPrivilege(string privilege, bool disable) {
			bool retVal;
			TokPriv1Luid tp;
			IntPtr hproc = GetCurrentProcess();
			IntPtr htok = IntPtr.Zero;
			retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
			tp.Count = 1;
			tp.Luid = 0;
			tp.Attr = disable ? SE_PRIVILEGE_DISABLED : SE_PRIVILEGE_ENABLED;
			retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
			retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
			int err = Marshal.GetLastWin32Error();
			if (err!=0) {
				FirmwareInfo.log.WriteLine("AdjustTokenPrivileges, errorCode="+err);
			}
			return retVal;
		}
	}

	internal static class AuthenticodeTools {
		[DllImport("Wintrust.dll", PreserveSig = true, SetLastError = false)]
		private static extern uint WinVerifyTrust(IntPtr hWnd, IntPtr pgActionID, IntPtr pWinTrustData);
		private static uint WinVerifyTrust(string fileName) {
			Guid wintrust_action_generic_verify_v2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
			uint result=0;
			using (WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(fileName,Guid.Empty))
			using (UnmanagedPointer guidPtr = new UnmanagedPointer(Marshal.AllocHGlobal(Marshal.SizeOf(typeof (Guid))), AllocMethod.HGlobal))
			using (UnmanagedPointer wvtDataPtr = new UnmanagedPointer(Marshal.AllocHGlobal(Marshal.SizeOf(typeof (WINTRUST_DATA))), AllocMethod.HGlobal))
			{
				WINTRUST_DATA data = new WINTRUST_DATA(fileInfo);
				IntPtr pGuid = guidPtr;
				IntPtr pData = wvtDataPtr;
				Marshal.StructureToPtr(wintrust_action_generic_verify_v2, pGuid, true);
				Marshal.StructureToPtr(data, pData, true);
				result = WinVerifyTrust(IntPtr.Zero, pGuid, pData);            
			}
			return result;
    	}
		public static bool IsTrusted(string fileName) {
			return WinVerifyTrust(fileName) == 0;
		}
	}

	internal struct WINTRUST_FILE_INFO : IDisposable {

		public WINTRUST_FILE_INFO(string fileName, Guid subject) {

			cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
			pcwszFilePath = fileName;
			if (subject != Guid.Empty) {
				pgKnownSubject = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
				Marshal.StructureToPtr(subject, pgKnownSubject, true);
			} else {
				pgKnownSubject = IntPtr.Zero;
			}
			hFile = IntPtr.Zero;
		}

		public uint cbStruct;

		[MarshalAs(UnmanagedType.LPTStr)]
		public string pcwszFilePath;
		public IntPtr hFile;
		public IntPtr pgKnownSubject;

		#region IDisposable Members
		public void Dispose() {
			Dispose(true);
		}

		private void Dispose(bool disposing) {
			if (pgKnownSubject != IntPtr.Zero) {
				Marshal.DestroyStructure(this.pgKnownSubject, typeof(Guid));
				Marshal.FreeHGlobal(this.pgKnownSubject);
			}
		}

		#endregion
	}

	enum AllocMethod
	{
		HGlobal, CoTaskMem
	};
	enum UnionChoice
	{
		File = 1, Catalog, Blob, Signer, Cert
	};
	enum UiChoice
	{
		All = 1, NoUI, NoBad, NoGood
	};
	enum RevocationCheckFlags
	{
		None = 0, WholeChain
	};
	enum StateAction
	{
		Ignore = 0, Verify, Close, AutoCache, AutoCacheFlush
	};
	enum TrustProviderFlags
	{
		UseIE4Trust = 1, NoIE4Chain = 2, NoPolicyUsage = 4, RevocationCheckNone = 16, RevocationCheckEndCert = 32,
		RevocationCheckChain = 64, RecovationCheckChainExcludeRoot = 128, Safer = 256, HashOnly = 512,
		UseDefaultOSVerCheck = 1024, LifetimeSigning = 2048
	};
	enum UIContext
	{
		Execute = 0, Install
	};

	[StructLayout(LayoutKind.Sequential)]

	internal struct WINTRUST_DATA : IDisposable
	{
		public WINTRUST_DATA(WINTRUST_FILE_INFO fileInfo) {
			this.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
			pInfoStruct = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
			Marshal.StructureToPtr(fileInfo, pInfoStruct, false);
			this.dwUnionChoice = UnionChoice.File;
			pPolicyCallbackData = IntPtr.Zero;
			pSIPCallbackData = IntPtr.Zero;
			dwUIChoice = UiChoice.NoUI;
			fdwRevocationChecks = RevocationCheckFlags.None;
			dwStateAction = StateAction.Ignore;
			hWVTStateData = IntPtr.Zero;
			pwszURLReference = IntPtr.Zero;
			dwProvFlags = TrustProviderFlags.Safer;
			dwUIContext = UIContext.Execute;
		}

		public uint cbStruct;
		public IntPtr pPolicyCallbackData;
		public IntPtr pSIPCallbackData;
		public UiChoice dwUIChoice;
		public RevocationCheckFlags fdwRevocationChecks;
		public UnionChoice dwUnionChoice;
		public IntPtr pInfoStruct;
		public StateAction dwStateAction;
		public IntPtr hWVTStateData;
		private IntPtr pwszURLReference;
		public TrustProviderFlags dwProvFlags;
		public UIContext dwUIContext;

		#region IDisposable Members
		public void Dispose() {
			Dispose(true);
		}

		private void Dispose(bool disposing) {
			if (dwUnionChoice == UnionChoice.File) {
				WINTRUST_FILE_INFO info = new WINTRUST_FILE_INFO();
				Marshal.PtrToStructure(pInfoStruct, info);
				info.Dispose();
				Marshal.DestroyStructure(pInfoStruct, typeof(WINTRUST_FILE_INFO));
			}
			Marshal.FreeHGlobal(pInfoStruct);
		}

		#endregion
	}

	internal sealed class UnmanagedPointer : IDisposable {

		private IntPtr m_ptr;
		private AllocMethod m_meth;
		internal UnmanagedPointer(IntPtr ptr, AllocMethod method) {
			m_meth = method;
			m_ptr = ptr;
		}

		~UnmanagedPointer() {
			Dispose(false);
		}

		#region IDisposable Members

		private void Dispose(bool disposing) {

			if (m_ptr != IntPtr.Zero) {
				if (m_meth == AllocMethod.HGlobal) {
					Marshal.FreeHGlobal(m_ptr);
				}
				else if (m_meth == AllocMethod.CoTaskMem) {
					Marshal.FreeCoTaskMem(m_ptr);
				}
				m_ptr = IntPtr.Zero;
			}

			if (disposing) {
				GC.SuppressFinalize(this);
			}
		}

		public void Dispose() {
			Dispose(true);
		}

		#endregion

		public static implicit operator IntPtr(UnmanagedPointer ptr) {
			return ptr.m_ptr;
		}
	}
	
	/** https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.2.0.pdf */
	public class FirmwareInfo {

		private static FileStream zipFile = null;
		private static ZipArchive zip = null;
		private static MemoryStream ms = new MemoryStream();
		public static readonly StreamWriter log = new StreamWriter(ms);

		private static void openZip() {
			zipFile = new FileStream("FirmwareInfoReport.zip", FileMode.Create, FileAccess.Write);
			zip = new ZipArchive(zipFile, ZipArchiveMode.Create);
		}

		private static void finishLog() {
			var entry = zip.CreateEntry("report.txt");
			String hash = "";
			using (var os = entry.Open()) {
				log.Flush();
				ms.Flush();
				byte[] report = ms.GetBuffer();
				report = slice(report, 0, (int)ms.Length);
				hash = computeSha256(report);
				os.Write(report, 0, report.Length);
				os.Flush();				
			}
			String authenticode = computeSha256(Encoding.UTF8.GetBytes(Process.GetCurrentProcess().ProcessName+":"+hash));
			using (var auth = zip.CreateEntry(" ").Open()) {
				byte[] buff = Encoding.UTF8.GetBytes(authenticode);
				auth.Write(buff, 0, buff.Length);
				auth.Flush();
			}
		}

		private static void closeZip() {
			zipFile.Flush();
			zipFile.Close();			
		}

		
		[DllImport("advapi32.dll", SetLastError=true)]
		static extern bool GetCurrentHwProfile(IntPtr fProfile);
		
		[DllImport("kernel32.dll", SetLastError=true)]
		static extern int GetSystemFirmwareTable(int FirmwareTableProviderSignature, int id, IntPtr pFirmwareTableEnumBuffer, int BufferSize);

		[DllImport("kernel32.dll", SetLastError=true)]
		static extern int EnumSystemFirmwareTables(int FirmwareTableProviderSignature, IntPtr pFirmwareTableEnumBuffer, int BufferSize);

		[DllImport("kernel32.dll", SetLastError=true)]
		static extern int GetFirmwareEnvironmentVariable(string lpName, string lpGuid, IntPtr pBuffer, int nSize);

		[DllImport("ntdll.dll", SetLastError=true)]
		static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, IntPtr Enabled);

		private static StringCollection efiFiles = new StringCollection();
		
		private static bool isPrintable(char ch) {
			const String PRINTABLE_CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`1234567890-=~@#$%^&*()_+[]\\;',./{}|:\"<>? ";
			return PRINTABLE_CHARS.IndexOf(ch)!=-1;
		}

		private static string computeSha256(byte[] bytes) {
			SHA256Managed hashProvider = new SHA256Managed();
        	byte[] hash = hashProvider.ComputeHash(bytes);
        	return toHex(hash, 0, Int32.MaxValue);
    	}

		private static String toHex(byte[] buf, int start, int limit) {
			StringBuilder hex = new StringBuilder();
			int len = buf.Length;
			if (limit > len) limit = len;
        	for (int i=start; i < limit; i++) {
            	hex.Append(String.Format("{0:x2}", buf[i]));
        	}
        	return hex.ToString();
		}

		private static String byteArrayToString(byte[] managedArray, bool onlyPrintable, int overrideStart) {
			StringBuilder sb = new StringBuilder();
			bool wasZero=false;
			for (int i=overrideStart; i < managedArray.Length; i++) {
				char ch = (char)managedArray[i];
				if (wasZero && ch==0) {
					sb.Append(" ");
					wasZero=false;
				}
				else {
					wasZero=ch==0;
				}
				if (!onlyPrintable || isPrintable(ch))
					sb.Append(ch);
			}
			return sb.ToString();
		}

		private static String byteArrayToString(byte[] managedArray, bool onlyPrintable) {
			return byteArrayToString(managedArray, onlyPrintable, 0);
		}

		private static void byteArrayToFile(byte[] managedArray, String filename) {
			var entry = zip.CreateEntry(filename);
			using (var os = entry.Open()) {
				os.Write(managedArray, 0, managedArray.Length);
				os.Flush();
			}			
		}
		private static String getMachineUuid() {
			IntPtr lHWInfoPtr = Marshal.AllocHGlobal(123);
			HWProfile lProfile=new HWProfile();
			Marshal.StructureToPtr(lProfile,lHWInfoPtr,false);
			string lText="";

			if (GetCurrentHwProfile(lHWInfoPtr)) {
				Marshal.PtrToStructure(lHWInfoPtr, lProfile);
				lText=lProfile.szHwProfileGuid.ToString();
			}
			Marshal.FreeHGlobal(lHWInfoPtr);
			return lText;
		}

		private static String findBiosInfo(byte[] arr) {
			/*VENDOR VERSION DD/MM/YYYY*/
			for (int i=0; i < arr.Length; i++) {
				char c = (char)arr[i];
				if (c=='/' && i+7 < arr.Length && (char)(arr[i+3])=='/' && i-2 > 0) {
					char d1 = (char)arr[i-2];
					char d2 = (char)arr[i-1];
					char m1 = (char)arr[i+1];
					char m2 = (char)arr[i+2];
					char y1 = (char)arr[i+4];
					char y2 = (char)arr[i+5];
					char y3 = (char)arr[i+6];
					char y4 = (char)arr[i+7];
					if (d1 >= '0' && d1 <= '3' && Char.IsDigit(d2) && Char.IsDigit(m1) && Char.IsDigit(m2)
						&& Char.IsDigit(y1) && Char.IsDigit(y2) && Char.IsDigit(y3) && Char.IsDigit(y3)) {
							StringBuilder sb = new StringBuilder();
							sb.Append(d1).Append(d2).Append("/").Append(m1).Append(m2).Append("/")
								.Append(y1).Append(y2).Append(y3).Append(y4);
							String dt = sb.ToString();
							int backRef = i-4;
							while (backRef>0 && arr[backRef]!=0) backRef--;
							sb.Clear();
							for (int k=backRef+1; k < i-3; k++) {
								char chr = (char)arr[k];
								if (isPrintable(chr))
									sb.Append(chr);
							}
							String ver = sb.ToString();
							int back = backRef-1;
							while (back>0 && arr[back]!=0 && isPrintable((char)arr[back])) back--;
							sb.Clear();
							for (int k=back+1; k < backRef; k++) {
								char chr = (char)arr[k];
								if (isPrintable(chr))
									sb.Append(chr);
							}
							String vendor = sb.ToString();
							return "vendor="+vendor+", version="+ver+", date="+dt;
						}
				}
			}
			return "unknown";
		}

		private static byte[] getFirmwareTable(String kind) {
			int id = (byte)kind[0] << 24 | (byte)kind[1] << 16 | (byte)kind[2] << 8 | (byte)kind[3];	  
			int expectedSize = 0;
			expectedSize = GetSystemFirmwareTable(id, 0, IntPtr.Zero, expectedSize);
			IntPtr pBuffer = Marshal.AllocHGlobal(expectedSize);
			GetSystemFirmwareTable(id, 0, pBuffer, expectedSize);
			byte[] managedArray = new byte[expectedSize];
			Marshal.Copy(pBuffer, managedArray, 0, expectedSize);
			Marshal.FreeHGlobal(pBuffer);
			return managedArray;
		}

		private static void bZero(IntPtr buf, int size) {
			for (int i=0; i < size; i++) {
				Marshal.WriteByte(IntPtr.Add(buf, i), 0);
			}
		}

		private static byte[] getFirmwareVariable(String name, String guid, bool warn) {
			int expectedSize = 32768;
			IntPtr pBuffer = Marshal.AllocHGlobal(expectedSize);
			bZero(pBuffer, expectedSize);
			expectedSize = GetFirmwareEnvironmentVariable(name, guid, pBuffer, expectedSize);
			int err = Marshal.GetLastWin32Error();
			if (err!=0 && warn) {
				log.WriteLine("GetFirmwareEnvironmentVariable errorCode="+err+" for "+name);
			}
			byte[] managedArray = new byte[expectedSize];
			Marshal.Copy(pBuffer, managedArray, 0, expectedSize);
			Marshal.FreeHGlobal(pBuffer);
			return managedArray;
		}

		private static byte[] getFirmwareVariable(String name, String guid) {
			return getFirmwareVariable(name, guid, true);
		}

		private static byte[] getFirmwareTable(String kind, String type) {
			int id = (byte)kind[0] << 24 | (byte)kind[1] << 16 | (byte)kind[2] << 8 | (byte)kind[3];
			int subtype =  (byte)type[3] << 24 | (byte)type[2] << 16 | (byte)type[1] << 8 | (byte)type[0];
			int expectedSize = 0;
			expectedSize = GetSystemFirmwareTable(id, subtype, IntPtr.Zero, expectedSize);
			//log.WriteLine("Expected size for "+kind+" "+type+" is "+expectedSize);
			IntPtr pBuffer = Marshal.AllocHGlobal(expectedSize);
			GetSystemFirmwareTable(id, subtype, pBuffer, expectedSize);
			byte[] managedArray = new byte[expectedSize];
			Marshal.Copy(pBuffer, managedArray, 0, expectedSize);
			Marshal.FreeHGlobal(pBuffer);
			return managedArray;
		}

		private static Dictionary<String, int> enumFirmwareTables(String kind) {
			int id = (byte)kind[0] << 24 | (byte)kind[1] << 16 | (byte)kind[2] << 8 | (byte)kind[3];	  
			int expectedSize = 0;
			expectedSize = EnumSystemFirmwareTables(id, IntPtr.Zero, expectedSize);
			IntPtr pBuffer = Marshal.AllocHGlobal(expectedSize);
			EnumSystemFirmwareTables(id, pBuffer, expectedSize);
			byte[] managedArray = new byte[expectedSize];
			Marshal.Copy(pBuffer, managedArray, 0, expectedSize);
			Marshal.FreeHGlobal(pBuffer);
			Dictionary<String, int> map = new Dictionary<string, int>();
			int ptr = 0;
			while (ptr < managedArray.Length) {
				if (ptr + 3 <= managedArray.Length) {
					StringBuilder sId = new StringBuilder(4);
					for (int i=0; i < 4; i++) {
						sId.Append((char)managedArray[ptr + i]);
					}
					String entry = sId.ToString();
					int count = map.ContainsKey(entry) ? map[entry] : 0;
					map[entry]=++count;
				}
				ptr += 4;
			}
			return map;
		}

		private static byte[] slice(byte[] b, int start, int end) {
			byte[] arr = new byte[end-start];
			int k=0;
			for (int i=start; i < end; i++) {
				arr[k]=b[i];
				k++;
			}
			return arr;
		}

		[DllImport("ntdll.dll", SetLastError = true)]
        private static extern UInt32 NtEnumerateSystemEnvironmentValuesEx(UInt32 function, [Out] Byte[] lpBuffer, ref int nSize);

		private static void dumpUEFIVars() {
			byte[] result = new byte[1024*1024];
			int size = result.Length;
			NtEnumerateSystemEnvironmentValuesEx(1, result, ref size);
            int p = 0;
			log.WriteLine("\nList of UEFI vars");
            while (true) {
            	int nextOffset = result[p+3] << 24 | result[p+2] << 16 | result[p+1] << 8 | result[p];
                if (nextOffset==0)
					break;
				Guid ns = new Guid(slice(result, p+4, p+4+16));
				String name = byteArrayToString(slice(result, p+20, p+nextOffset - 1), true, 0).Trim();
                log.WriteLine("UEFI VAR "+ns+"::"+name);
				byte[] arr = getFirmwareVariable(name, "{"+ns+"}");
				byteArrayToFile(arr, ns+"_"+name+".dat");
    			p += nextOffset;
            }
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName, uint cchBufferLength);
		[DllImport("kernel32.dll", SetLastError = true)]
   		static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);
		[DllImport("kernel32.dll", SetLastError = true)]
    	static extern bool FindVolumeClose(IntPtr hFindVolume);

		[DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
  		[return: MarshalAs(UnmanagedType.Bool)]
 		public extern static bool GetVolumeInformation(string rootPathName, StringBuilder volumeNameBuffer,
    		int volumeNameSize, out uint volumeSerialNumber, out uint maximumComponentLength,
			out int fileSystemFlags, StringBuilder fileSystemNameBuffer, int nFileSystemNameSize);
		[DllImport("kernel32.dll", SetLastError=true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool GetVolumePathNamesForVolumeName(string lpszVolumeName,
        	StringBuilder lpszVolumePathNames, uint cchBuferLength, ref UInt32 lpcchReturnLength);

		[DllImport("kernel32.dll", SetLastError=true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool SetVolumeMountPointA(string drivePath, string volume);

		[DllImport("kernel32.dll", SetLastError=true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool DeleteVolumeMountPointA(string volume);

		private static StringCollection getUEFIVolumes() {
			StringCollection names = new StringCollection();
			StringBuilder sb = new StringBuilder(1024, 1024);
			IntPtr handle = FindFirstVolume(sb, 1024);
			do {
				String volName = sb.ToString();
                StringBuilder volname = new StringBuilder(261);
				StringBuilder fsname = new StringBuilder(261);
				uint sernum, maxlen;
				int flags;
				if(GetVolumeInformation(sb.ToString(), volname, volname.Capacity, 
				 out sernum, out maxlen, out flags, fsname, fsname.Capacity)) {
					string fsnamestr = fsname.ToString();
					if ("FAT32".Equals(fsnamestr)) {
						StringBuilder driveLetters = new StringBuilder(128,128);
						UInt32 len = 0;
						bool status = GetVolumePathNamesForVolumeName(volName, driveLetters, 128, ref len);
						if (driveLetters.Length > 0) {
							if (Directory.Exists(driveLetters[0]+":\\EFI")) {
								log.WriteLine("SECURITY_ALERT: Volume "+driveLetters+" contains EFI directory");
								bool res = DeleteVolumeMountPointA(driveLetters.ToString());
								if (!res) {
									log.WriteLine("Can't umount volume "+driveLetters+": "+Marshal.GetLastWin32Error());
								}
							}
						}
						else { // no drive letter assigned, likely UEFI partition
							names.Add(volName);
						}
					}
				}
			}
			while (FindNextVolume(handle, sb, 1024));
			FindVolumeClose(handle);
			return names;
		}

		/** see: https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0
			https://formats.kaitai.io/efivar_signature_list/csharp.html */
		private static void processEsl(byte[] b) {
			byte[] EFI_CERT_SHA256_GUID = { 0x26, 0x16, 0xC4, 0xC1,  0x4C, 0x50,  0x92, 0x40,  0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28 };
			byte[] EFI_CERT_X509_GUID = { 0xA1, 0x59, 0xC0, 0xA5,  0xE4, 0x94,  0xA7, 0x4A,  0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72 };
			byte[] EFI_CERT_SHA512_GUID = { 99, 191, 109, 68, 2, 37, 218, 76, 188, 250, 36, 101, 210, 176, 254, 157 };
			byte[] EFI_CERT_RSA2048_GUID = { 232, 102, 87, 60, 156, 38, 52, 78, 170, 20, 237, 119, 110, 133, 179, 182 };
			int type1 = 0, type2 = 0;
			for (int i=0; i < 16; i++) {
				if (b[i] == EFI_CERT_SHA256_GUID[i]) type1++;
				else if (b[i] == EFI_CERT_X509_GUID[i]) type2++;
			}
			int sigListSize = b[19] << 24 | b[18] << 16 | b[17] << 8 | b[16];
			int sigHdrSize = b[23] << 24 | b[22] << 16 | b[21] << 8 | b[20];
			int sigSize = b[27] << 24 | b[26] << 16 | b[25] << 8 | b[24];
			int sigCount = (sigListSize - 0x1C) / sigSize;
			if (type1==16 || type2==16) {
				log.WriteLine("Known GUID in ESL: "+new Guid(slice(b, 0, 16))+", size="+b.Length+
				", sha-256="+computeSha256(b)+", number of entries="+sigCount);
			}
			else {
				log.WriteLine("Uknown GUID in ESL: "+new Guid(slice(b, 0, 16))+", size="+b.Length+
				", sha-256="+computeSha256(b)+", number of entries="+sigCount);
			}
			
			int _base = 0;
			for (int i=0; i < sigCount; i++) {
				String sigOwner = new Guid(slice(b, 28+_base, 28+16+_base)).ToString();
				try {
					var cert = new X509Certificate2(slice(b, 44+_base, b.Length));
					log.WriteLine("-> Entry #"+i+" for "+sigOwner+" is \n--------\n"+cert+"\n--------");
				}
				catch (Exception e) {
					int hashSize = sigSize - 16;
					String hash = hashSize % 8 == 0 ? toHex(b, 44+_base, 44+_base + hashSize) : "<invalid>";
					log.WriteLine("-> Entry #"+i+" for "+sigOwner+" is not X509 ("+e.Message+"). As Hash("+hashSize+") it is "+hash);
					// TODO: DER, RSA					
				}
				_base += sigSize;
			}
		}
		
		private static void analyzeBIOS() {
			log.WriteLine("Machine uniquely identified as "+getMachineUuid());
			byte[] arr = getFirmwareTable("RSMB");
			byteArrayToFile(arr, "SMBIOS.dat");
			log.WriteLine("SMBIOS size="+arr.Length+", SHA-256="+computeSha256(arr));
			String biosVer = findBiosInfo(arr);
			log.WriteLine("-> Extracted BIOS info: "+findBiosInfo(arr));

			var map = enumFirmwareTables("ACPI");
			log.WriteLine("Enumeration of ACPI tables. If some entry is duplicated Win32 API only allows to get 1st one.");		
			foreach(String key in map.Keys) {
				arr = getFirmwareTable("ACPI", key);
				int cnt = map[key];
				log.WriteLine("-> ACPI "+key+" 1 of "+cnt+": size="+arr.Length+", SHA-256="+computeSha256(arr));
				byteArrayToFile(arr, "ACPI_"+key+".dat");
			}
		}

		/* See page 82 https://uefi.org/sites/default/files/resources/UEFI_Spec_2_9_2021_03_18.pdf */
		private static void analyzeUEFIBootEntries() {
			byte[] arr = getFirmwareVariable("BootOrder", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
			if (arr.Length > 0) {
				for (int i=0; i < arr.Length; ) {
					int index = arr[i+1] << 8 | arr[i];
					String entry = "Boot" + $"{index:X4}";
					log.WriteLine("\nBootOrder entry "+entry);
					byte[] content = getFirmwareVariable(entry, "{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
					StringBuilder desc = new StringBuilder();
					int k=6;
					for (; k < content.Length; k++) {
						char c = (char)(content[k]);
						if (isPrintable(c)) {
							desc.Append(c);
						}
						if (c==0 && k+1 < content.Length && content[k+1]==0)
							break;
					}
					int filePathListLen = content[6] << 8 | content[5];
					int hdrBase = k+3;
					int type = content[hdrBase];
					int subtype = content[hdrBase+1];
					int len = content[hdrBase+3] << 8 | content[hdrBase+2];
					string[] typeDesc = {
						"0x00 Invalid type",
						"0x01 Hardware Device Path",
						"0x02 ACPI Device Path",
						"0x03 Messaging Device Path",
						"0x04 Media Device Path",
						"0x05 BIOS Boot Specification Device Path"
					};
					log.WriteLine("-> name: "+desc.ToString());

					if (type > 0 && type < 6) {
						String typeText = "-> EFI_DEVICE_PATH_PROTOCOL: type="+typeDesc[type]+", subtype="+subtype+", len="+len;
						// https://dox.ipxe.org/DevicePath_8h_source.html
						log.WriteLine(typeText);
					}
					else {
						String typeText = "-> EFI_DEVICE_PATH_PROTOCOL: type="+type+", subtype="+subtype+", len="+len;
						log.WriteLine(typeText);
					}
					// see Load Option: https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html
					// https://github.com/rhboot/efibootmgr/blob/main/src/efibootmgr.c
					// https://morfikov.github.io/post/jak-dodac-wlasne-klucze-dla-secure-boot-do-firmware-efi-uefi-pod-linux/
					String optionalText = byteArrayToString(content, true, hdrBase+len);
					int start = optionalText.IndexOf("\\EFI\\");
					int end = optionalText.IndexOf(".efi", start+5);
					if (start!=-1 && end!=-1) {
						String efiFile = optionalText.Substring(start, end-start+4);
						efiFiles.Add(efiFile);
						log.WriteLine("-> EFI file: "+efiFile);
					}
					else if (start!=-1) {
						int z=start;
						for (; z < optionalText.Length; z++) {
							char x = optionalText[z];
							if (!isPrintable(x))
								break;
						}
						String efiFile = optionalText.Substring(start, z-start).Trim();
						efiFiles.Add(efiFile);
						log.WriteLine("-> EFI file: "+efiFile);
					}					
					i+=2;
					// https://answers.microsoft.com/en-us/windows/forum/all/deducting-and-preventing-blacklotus-bootkit/947f7f23-7a84-4bce-8668-acb1b8c18c25
				}
			}
		}

		private static void File_CopyToZip(String path, String exeFile) {
			var entry = zip.CreateEntry(exeFile);
			using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read)) {
				using (var os = entry.Open()) {
					byte[] buff = new byte[128*1024];
					int n = 0;
					while (( n = fs.Read(buff, 0, buff.Length)) > 0) {
						os.Write(buff, 0, n);
					}
					os.Flush();
				}
			}	
		}

		private static String getFreeDiveLetter() {
			const String letters = "UVWXYZABHIJKLMNOPQRST";
			foreach (char c in letters) {
				if (!Directory.Exists(c+":\\")) {
					return c+":";
				}
			}
			return "A:";
		}

		private static void analyzeUEFIVolumes() {
			log.WriteLine("\nAnalyzing UEFI volumes");
			String letter = getFreeDiveLetter();
			foreach (String vol in getUEFIVolumes()) {
				bool res = SetVolumeMountPointA(letter+"\\", vol);
				if (!res) {
					log.WriteLine("Failed to analyze volume "+vol+": "+Marshal.GetLastWin32Error());
				}
				else {
					log.WriteLine("-> "+vol);
					foreach (String f in efiFiles) {
						String path = letter+f;
						StringBuilder fileInfo = new StringBuilder();
						if (!File.Exists(path)) {
							fileInfo.Append("File not found: "+f);
						}
						else {
							try {
								FileInfo fi = new FileInfo(path);
								fileInfo.Append("File "+f+": size=")
									.Append(fi.Length)
									.Append(", created=")
									.Append(fi.CreationTime)
									.Append(", modified=").Append(fi.LastWriteTime);
								using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read)) {
									SHA256Managed hashProvider = new SHA256Managed();
									byte[] hash = hashProvider.ComputeHash(fs);
									StringBuilder hashString = new StringBuilder();
									foreach (byte x in hash) {
										hashString.Append(String.Format("{0:x2}", x));
									}
									fileInfo.Append(", sha256=").Append(hashString.ToString());
									String exeFile = hashString.ToString()+".exe";
									File_CopyToZip(path, exeFile);
									File.Copy(path, exeFile);
									// https://www.platformsecuritysummit.com/2018/speaker/kiper/PSEC2018-UEFI-Secure-Boot-shim-Xen-Daniel-Kiper.pdf
									bool trusted = AuthenticodeTools.IsTrusted(exeFile);
									File.Delete(exeFile);
									log.WriteLine("Is EFI file "+f+" trusted? "+trusted);
									// https://stackoverflow.com/questions/15024583/how-to-retrieve-files-digital-signature-information
									try {
										FileSignatureInfo sigInfo = FileSignatureInfo.GetFromFileStream(fs);
										if (sigInfo.SigningCertificate==null) {
											fileInfo.Append(", no signature cert, state=").Append(sigInfo.State);
										}
										else {
											log.WriteLine("Signature: state="+sigInfo.State+", details=\n--------\n"+
											sigInfo.SigningCertificate+"\n--------"); // SignatureState.SignedAndTrusted
										}
									}
									catch (Exception e) {
										fileInfo.Append(", error checking sig="+e.Message);
									}
									// https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0
									
									foreach (FileInfo finfo in Directory.GetParent(path).EnumerateFiles()) {
										if (!finfo.FullName.Equals(path)) {
											if ((finfo.Attributes & FileAttributes.Directory) == FileAttributes.Directory) {
												log.WriteLine("Inside EFI dir another dir: "+finfo);
											}
											else {
												log.WriteLine("* Inside EFI dir is : "+finfo.FullName);
												try {
													log.WriteLine(getSignedFileInfo(finfo.FullName));
												}
												catch (Exception exc) {
													log.WriteLine("Error listing "+finfo.FullName+": "+exc.Message);
												}
											}
										}
									}									
								}
							}
							catch (Exception e) {
								log.WriteLine("Error for "+path+": "+e.Message);
							}
						}
						log.WriteLine(fileInfo);
					}
					res = DeleteVolumeMountPointA(letter+"\\");
					if (!res)
						log.WriteLine("Failed to unmount volume "+vol+": "+Marshal.GetLastWin32Error());
				}
			}
		}

		private static void analyzeCryptoVars() {
			// https://blog.hansenpartnership.com/the-meaning-of-all-the-uefi-keys/
			// https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/uefi-validation-option-rom-validation-guidance?view=windows-10
			// https://github.com/mjg59/efitools/blob/master/sign-efi-sig-list.c
			String[] entries = { "KEK", "KEKDefault", "PK", "PKDefault", "db", "dbx", "dbDefault", "dbxDefault" };
			String[] namespaces = { "{8be4df61-93ca-11d2-aa0d-00e098032b8c}", "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}"};

			// https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11

			foreach (String ns in namespaces) {
				foreach (String entry in entries) {
					byte[] arr = getFirmwareVariable(entry, ns);
					if (arr.Length>0) {
						log.WriteLine("\nProcessing ((("+entry+"))) in namespace "+ns);
						byteArrayToFile(arr, entry+".esl");
						processEsl(arr);
					} else {
						log.WriteLine("\nCouldn't get ((("+entry+"))) in namespace "+ns);
					}
				}
			}
		}

		[DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumDeviceDrivers([Out] IntPtr[] ImageBases, [In] int Size, [Out] out int Needed);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetDeviceDriverBaseName([In] IntPtr ImageBase, [Out] StringBuilder FileName, [In] int Size);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int GetDeviceDriverFileName([In] IntPtr ImageBase, [Out] StringBuilder FileName, [In] int Size);

		private static String getSignedFileInfo(String f) {
			StringBuilder fileInfo = new StringBuilder();
			if (!File.Exists(f)) {
				return "Error: File missing on path '"+f+"'";
			}
			FileInfo fi = new FileInfo(f);
			fileInfo.Append("File "+f+": size=")
				.Append(fi.Length)
				.Append(", created=")
				.Append(fi.CreationTime)
				.Append(", modified=").Append(fi.LastWriteTime);
			using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read)) {
				SHA256Managed hashProvider = new SHA256Managed();
				byte[] hash = hashProvider.ComputeHash(fs);
				StringBuilder hashString = new StringBuilder();
				foreach (byte x in hash) {
					hashString.Append(String.Format("{0:x2}", x));
				}
				fileInfo.Append(", sha256=").Append(hashString.ToString());
				fs.Seek(0L, SeekOrigin.Begin);
				try {
					FileSignatureInfo sigInfo = FileSignatureInfo.GetFromFileStream(fs);
					if (sigInfo.SigningCertificate==null) {
						fileInfo.Append(", no signature cert, state=").Append(sigInfo.State);
					}
					else {
						fileInfo.Append(", sigCertSubject=(").Append(sigInfo.SigningCertificate.SubjectName.Name).Append(")");
						fileInfo.Append(", sigCertSerialNumber=").Append(sigInfo.SigningCertificate.SerialNumber);
						fileInfo.Append(", sigCertThumbprint=").Append(sigInfo.SigningCertificate.Thumbprint);
						fileInfo.Append(", sigCertIssuer=(").Append(sigInfo.SigningCertificate.IssuerName.Name).Append(")");;
						fileInfo.Append(", sigCertHash=").Append(sigInfo.SigningCertificate.GetCertHashString());
						fileInfo.Append(", sigCertIssuedAt=").Append(sigInfo.SigningCertificate.NotBefore);
					}
				}
				catch (Exception e) {
					fileInfo.Append(", error checking sig="+e.Message);
				}				
			}
			return fileInfo.ToString();
		}
		private static void analyzeDrivers() {
			int size = 0;
			log.WriteLine("\nGetting drivers info");
			EnumDeviceDrivers(null, size, out size);
			IntPtr[] imageBases = new IntPtr[size / IntPtr.Size];
			StringBuilder drvName = new StringBuilder(128, 128);
			if (EnumDeviceDrivers(imageBases, size, out size)) {
				foreach (IntPtr imageBase in imageBases) {
					drvName.Clear();
					GetDeviceDriverBaseName(imageBase, drvName, 128);
					String name = drvName.ToString().Trim();
					drvName.Clear();
					GetDeviceDriverFileName(imageBase, drvName, 128);
					String file = drvName.ToString().Trim().Replace("\\SystemRoot\\", "%SystemRoot%\\");
					file = Environment.ExpandEnvironmentVariables(file);
					try {
						log.WriteLine("Driver="+name+", "+getSignedFileInfo(file));
					}
					catch (Exception e) {
						log.WriteLine("Driver="+name+", File="+file+", error getting details="+e.Message);
					}
				}
			}
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
		[DllImport("Kernel32.dll")]
    	private static extern bool QueryFullProcessImageName([In] IntPtr hProcess, [In] uint dwFlags,
			[Out] StringBuilder lpExeName, [In, Out] ref uint lpdwSize);

		private static string GetFileNameFromHandle(IntPtr handle, StringBuilder fileNameBuilder, uint size) {
			fileNameBuilder.Clear();
			uint _size = size;
			return QueryFullProcessImageName(handle, 0, fileNameBuilder, ref _size) ? fileNameBuilder.ToString().Trim() : null;
    	}

		[DllImport("kernel32.dll", SetLastError=true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool CloseHandle(IntPtr hObject);

		private static void analyzeCoreBootFiles() {
			String[] files = { "winload.efi", "winload.exe", "winresume.efi", "winresume.exe" };
			log.WriteLine("\nAnalyzing core boot files");
			foreach (String f in files) {
				String file = Environment.ExpandEnvironmentVariables("%windir%\\System32\\"+f);
				log.WriteLine(getSignedFileInfo(file));
				file = Environment.ExpandEnvironmentVariables("%windir%\\System32\\Boot\\"+f);
				log.WriteLine(getSignedFileInfo(file));
			}
		}

		private static void analyzeProcesses() {
			log.WriteLine("\nGetting info about processes");
			StringBuilder fName = new StringBuilder(1024, 1024);
			Dictionary<String,bool> alreadySeen = new Dictionary<string, bool>();
			foreach (Process p in Process.GetProcesses()) {
				String name = p.ProcessName;
				String file = p.StartInfo.FileName;
				if (file==null || file.Length==0)
					file = name.EndsWith(".exe") || name.EndsWith("com") ? name : name+".exe";
				const int PROCESS_VM_READ = 0x00000010;
        		const int PROCESS_QUERY_INFORMATION = 0x00000400;
				IntPtr handle = IntPtr.Zero;
				try {
					handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
					int errCode = Marshal.GetLastWin32Error();
					if (errCode!=0) {
						log.WriteLine("Handle error for "+name+" and file "+file+": "+errCode);
					}
					String fileName = GetFileNameFromHandle(handle, fName, 1024);
					errCode = Marshal.GetLastWin32Error();
					if (errCode!=0) {
						log.WriteLine("FileName error for "+name+" and file "+file+": "+errCode);
					}
					if (fileName!=null) {
						bool seen = alreadySeen.ContainsKey(fileName);
						alreadySeen[fileName]=true;
						log.WriteLine("Proces "+p.Id+"="+name+", "+(seen ? "already seen" : getSignedFileInfo(fileName)));
					}
					else {
						log.WriteLine("Proces "+p.Id+"="+name+", File="+file+", Path unknown so assuming %windr%");
						fileName = Environment.ExpandEnvironmentVariables("%windir%\\System32\\"+file);
						log.WriteLine("Proces "+p.Id+"="+name+", "+getSignedFileInfo(fileName));
					}
				}
				catch (Exception e) {
					log.WriteLine("Proces "+p.Id+"="+name+", File="+file+", error getting details="+e.Message);
				}
				finally {
					if (handle.ToInt32()!=0)
						CloseHandle(handle);
				}
			}
		}

		private static void dumpCertificates() {
			MemoryStream baos = new MemoryStream();
			StreamWriter sw = new StreamWriter(baos);
			var entry = zip.CreateEntry("certificates.txt");
			X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly);
			foreach (X509Certificate2 c in store.Certificates) {
				sw.WriteLine("--------");
				sw.WriteLine(c.ToString());
			}
			using (var os = entry.Open()) {
				sw.Flush();
				baos.Flush();
				byte[] content = baos.GetBuffer();
				os.Write(content, 0, content.Length);
				os.Flush();
			}	
		}

		static void Main(string[] args) {
			Console.WriteLine("---- FirmwareInfo 0.9.001 ----");
			if (!AdjPriv.SetPrivilege("SeSystemEnvironmentPrivilege", false)) {
				Console.WriteLine("This program must be run with elevated privileges. Consider executing it again.");
			}
			Console.WriteLine("> Generating report (start="+DateTime.Now+")");
			openZip();
			analyzeBIOS();			
			analyzeUEFIBootEntries();
			dumpUEFIVars();
			analyzeCryptoVars();
			analyzeUEFIVolumes();
			analyzeCoreBootFiles();
			analyzeDrivers();
			analyzeProcesses();
			dumpCertificates();
			finishLog();
			closeZip();
			Console.WriteLine("> Done (end="+DateTime.Now+"). Please open with 7zip.");
		}		
	}
}
