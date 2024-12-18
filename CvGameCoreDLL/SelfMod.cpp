// smcpoc: New implementation file; see comment in header.
#include "CvGameCoreDLL.h"
#include "SelfMod.h"
// This should arguably go in CvGameCoreDLL.h instead ...
#include <algorithm>
// ... and this in FAssert.h, but let's try to keep our changes local. */
#define FErrorMsg(msg) FAssertMsg(false, msg)

Civ4BeyondSwordMods smc::BtS_EXE;

namespace
{
/*	This class seems like an elegant way of ensuring that virtual memory protections
	are restored at the end */
class RuntimePatch : boost::noncopyable
{
public:
	virtual ~RuntimePatch() { restorePageProtections(); }
	virtual void apply()=0;

protected:
	bool unprotectPage(LPVOID pAddress, SIZE_T uiSize,
		DWORD ulNewProtect = PAGE_EXECUTE_READWRITE)
	{
		/*	Getting a segmentation fault when writing to the text segment under
			Win 8.1. Probably the same on all Windows versions that anyone still uses.
			Need to unprotect the virtual memory page first. Let's hope that this
			long outdated version of VirtualProtect from WinBase.h (nowadays located
			in Memoryapi.h) will still do the trick on recent Win versions. */
		DWORD uiOldProtect; // I get PAGE_EXECUTE_READ here
		if (VirtualProtect(pAddress,
			/*	Will affect an entire page, not just the few bytes we need. Through
				SYSTEM_INFO sysInfo; GetSystemInfo(&sysInfo); sysInfo.dwPageSize;
				I see a page size of 4 KB. */
			uiSize, ulNewProtect, &uiOldProtect) == 0)
		{
			FErrorMsg("Failed to unprotect memory for runtime patch");
			return false;
		}
		/*	A check at VirusTotal.com makes me hopeful that merely calling
			VirtualProtect in some capacity won't make our DLL suspicious to
			static virus scans. To make issues with analyses of runtime memory
			less likely - and to restore protections against accidental memory
			accesses by other parts of the DLL - let's remember what protections
			we've changed and revert them asap. */
		m_aPageProtections.push_back(PageProtection(pAddress, uiSize, uiOldProtect));
		return true;
	}

private:
	struct PageProtection
	{
		PageProtection(LPVOID pAddress, SIZE_T uiSize, DWORD uiProtect)
			:	m_pAddress(pAddress), m_uiSize(uiSize), m_uiProtect(uiProtect) {}
		LPVOID m_pAddress;
		SIZE_T m_uiSize;
		DWORD m_uiProtect;
	};
	std::vector<PageProtection> m_aPageProtections;
	void restorePageProtections()
	{
		for (size_t i = 0; i < m_aPageProtections.size(); i++)
		{
			DWORD uiDummy;
		#ifdef FASSERT_ENABLE
			int iSuccess =
		#endif
			 VirtualProtect(m_aPageProtections[i].m_pAddress, m_aPageProtections[i].m_uiSize,
					m_aPageProtections[i].m_uiProtect, &uiDummy);
			FAssertMsg(iSuccess != 0, "Failed to restore memory protection");
		}
	}
};

class PlotIndicatorSizePatch : RuntimePatch
{
public:
	PlotIndicatorSizePatch(int iScreenHeight) : m_iScreenHeight(iScreenHeight) {}
	void apply() // override
	{
		/*	Cache (Performance probably no concern, but best not to fiddle
			with memory protections unnecessarily.) */
		static PlotIndicatorSize ffMostRecentBaseSize;

		/*	Size values for plot indicators shown onscreen and offscreen that are
			hardcoded in the EXE. These go through a bunch of calculations,
			only part of which I've located in the debugger. Essentially,
			there appears to be an adjustment proportional to the screen height. */
		PlotIndicatorSize ffBaseSize(42, 68);
		bool bAdjustToFoV = true;
		bool bAdjustToRes = false;
	#ifdef BUG_OPTIONS
		{
			int iUserChoice = BUGOption::getValue("MainInterface__PlotIndicatorSize");
			switch (iUserChoice)
			{
			case 0: ffBaseSize.onScreen -= 2; break; // "automatic" behavior
			case 1: std::swap(bAdjustToFoV, bAdjustToRes); break; // BtS behavior
			/*	Note that this formula ignores how the choices are labeled.
				That menu text needs to be kept consistent with our code here. */
			default: ffBaseSize.onScreen = 15 + 5 * static_cast<float>(iUserChoice);
			}
		}
	#else
		/*	Subtract a little b/c the BtS size is a bit too big overall,
			i.e. even on the lowest resolution. */
		ffBaseSize.onScreen -= 2;
	#endif
		/*	The EXE will adjust to height. Rather than try to change that in the EXE,
			we'll proactively cancel out the adjustment. */
		if (!bAdjustToRes)
		{
			/*	Current screen height relative to the height that the UI was
				most optimized for */
			float fHeightRatio = m_iScreenHeight / 768.f;
			ffBaseSize.onScreen = ffBaseSize.onScreen / fHeightRatio;
					/*	Could use this divisor to not cancel it out entirely -
						but the adjustment really just seems to be a bad idea. */
					// std::pow(fHeightRatio, 0.85f)
		}
		/*	[This part is aimed at BUG integration but does no harm w/o BUG.]
			FoV correlates with screen size, (typical) camera distance and
			the player's distance from the screen. And BtS seems to make a small
			adjustment based on FoV and camera distance too (probably
			not explicitly). So it's hard to reason about this adjustment.
			In my tests, it has had the desired result of making the diameters
			about one quarter of a plot's side length. */
		if (bAdjustToFoV)
		{
			float fTypicalFoV = 40;
			ffBaseSize.onScreen *= std::min(2.f, std::max(0.5f,
					std::sqrt(fTypicalFoV / GC.getFIELD_OF_VIEW())));
		}
		/*	(I'm not going to dirty the globe layer in response to a FoV change - that
			would probably cause stuttering while the player adjusts the FoV slider.) */
	#ifdef BUG_OPTIONS
		{
			int iUserChoice = BUGOption::getValue("MainInterface__OffScreenUnitSizeMult");
			if (iUserChoice == 7)
			{	// Meaning "disable". 0 size seems to do accomplish that.
				ffBaseSize.offScreen = 0;
			}
			else ffBaseSize.offScreen = ffBaseSize.onScreen * (0.8f + 0.2f * iUserChoice);
		}
	#else
		ffBaseSize.offScreen = ffBaseSize.onScreen * 1.4f;
	#endif

		if (ffBaseSize.equals(ffMostRecentBaseSize))
			return;
		ffMostRecentBaseSize = ffBaseSize;

		/*	The onscreen size is hardcoded as an immediate operand (in FP32 format)
			in three places and the offscreen size in one place.
			|Code addr.| Disassembly						| Code bytes
			------------------------------------------------------------------------------
			 00464A08	push 42280000h						 68 00 00 28 42
			 004B76F4		(same as above)
			 00496DEB	mov dword ptr [esi+17Ch],42280000h	 C7 86 7C 01 00 00 00 00 28 42
			 0049905F	push 42880000h						 68 00 00 88 42
			------------------------------------------------------------------------------
			One can get the debugger close to the first location by setting a breakpoint
			at the end of CvPlayer::getGlobeLayerColors. The second is triggered by
			interface messages that show a plot indicator; a breakpoint in
			CvTalkingHeadMessage::getOnScreenArrows should help. The third one seems
			to be reached in all cases, look for a call to 00496DB0.
			The fourth one is triggered by selecting any unit. */
		uint aCodeAdresses[] = {
			0x00464A08, 0x004B76F4, 0x00496DEB, 0x0049905F
		};
		// The data we need to change is not right at the start
		uint aOperandOffsets[ARRAYSIZE(aCodeAdresses)] = {
					1,			1,			6,			1
		};

		int iNeedleOffset = 0;
		int aAdressOffsets[4] = {};
		/*	Before applying our patch, let's confirm that the code is layed out
			in memory as we expect it to be. */
		if (!testCodeLayout())
		{
			/*	Could be that we're dealing with PitBoss - graphics won't matter then;
				or the default Steam version (i.e. not the "unsupported beta") -
				this we can try to work out; or something unknown, maybe some obscure
				East Asian edition or just not properly patched to BtS 3.19. */
			/*	25 instructions near the start of the function that calls
				CvPlayer::getGlobeLayerColors. This is a fairly long sequence w/o any
				absolute addresses in operands. After this sequence, there are a bunch
				of DLL calls, the last one being CvPlayer::getGlobeLayerColors.
				I've verified that this sequence exists in the Steamless (unpacked)
				version of the Steam BtS EXE on disk, namely at 0x00464F88, i.e. at
				an offset of 1616. */
			byte aNeedleBytes[] = {
				0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0x89, 0x25, 0x00, 0x00,
				0x00, 0x00, 0x83, 0xEC, 0x68, 0x53, 0x55, 0x56, 0x57, 0x33, 0xFF,
				0x89, 0x7C, 0x24, 0x54, 0x89, 0x7C, 0x24, 0x58, 0x89, 0x7C, 0x24,
				0x5C, 0x89, 0xBC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x89, 0x7C, 0x24,
				0x44, 0x89, 0x7C, 0x24, 0x48, 0x89, 0x7C, 0x24, 0x4C, 0x8D, 0x54,
				0x24, 0x40, 0x52, 0xC6, 0x84, 0x24, 0x84, 0x00, 0x00, 0x00, 0x01,
				0x8B, 0x41, 0x04, 0x8D, 0x54, 0x24, 0x54, 0x52, 0x50, 0x8B, 0x41,
				0x08, 0x50 
			};
			// Where we expect the needle at iAddressOffset=0
			uint const uiStartAddress = 0x00464938;
			// How big an iAddressOffset we contemplate
			int const iMaxAbsOffset = 256 * 1024;
			// Base address of the EXE. Reading below that results in a crash.
			int const iLowAddressBound = 0x00400000;
			// I see mostly just zeros above this address in the VS Memory window
			int const iHighAddressBound = 0x0FFFFFFF;
			if (((int)uiStartAddress) >= iLowAddressBound &&
				((int)uiStartAddress) <= iHighAddressBound)
			{
				int const iMaxSubtrahend = std::min(iMaxAbsOffset, static_cast<int>(
						uiStartAddress - iLowAddressBound));
				int const iMaxAddend = std::min(iMaxAbsOffset, static_cast<int>(
						iHighAddressBound - uiStartAddress));
				int const iHaystackBytes = iMaxSubtrahend + iMaxAddend;
				byte* pHaystackBytes = new byte[iHaystackBytes];
				for (int iOffset = -iMaxSubtrahend; iOffset < iMaxAddend; iOffset++)
				{
					pHaystackBytes[iOffset + iMaxSubtrahend] =
							reinterpret_cast<byte*>(uiStartAddress)[iOffset];
				}
				// No std::begin, std::end until C++11
				byte* const pHaystackEnd = pHaystackBytes + iHaystackBytes;
				byte* pos = std::search(
						pHaystackBytes, pHaystackEnd,
						aNeedleBytes, aNeedleBytes + ARRAYSIZE(aNeedleBytes));
				if (pos == pHaystackEnd)
				{
					FErrorMsg("Failed to locate plot indicator code bytes in EXE");
					return;
				}
				iNeedleOffset = ((int)std::distance(pHaystackBytes, pos))
						- iMaxSubtrahend;
			}
			else FErrorMsg("uiStartAddress doesn't look like a code address");
			/*	Run our initial test again to be on the safe side?
				Not likely to succeed; these offsets only work locally. */
			/*if (!testCodeLayout(iAddressOffset))
			{
				FErrorMsg("Address offset likely incorrect");
				return;
			}*/
			/*	Actually, looking at the (non-beta) Steam EXE, our offset will
				only work for the first of the four code locations to be modified.
				So I'll only use that offset as a confirmation that we're dealing
				with Steam and hardcode the offsets for Steam. Note that I haven't
				been able to test those at runtime - I've only searched the unpacked
				(through Steamless) binary with a hexeditor. */
			int const iSteamNeedleOffset = 1616;
			if (iNeedleOffset != iSteamNeedleOffset)
			{
				/*	I don't think we should proceed when it's unclear what version
					we're dealing with. In particular when this longer pattern is
					found just where we expected it (offset 0) while the quicker
					initial test failed. */
				FAssertMsg(iNeedleOffset == iSteamNeedleOffset,
						"Unexpected code layout of the EXE; not supported for now.");
				return;
			}
			aAdressOffsets[0] = iSteamNeedleOffset;
			aAdressOffsets[1] = 704;
			aAdressOffsets[2] = 544;
			aAdressOffsets[3] = 544;
		}

		// Finally apply the actual patch
		for (int i = 0; i < ARRAYSIZE(aCodeAdresses); i++)
		{
			float fSize = (i >= 3 ? ffBaseSize.offScreen : ffBaseSize.onScreen);
			uint uiCodeAddress = aCodeAdresses[i] + aOperandOffsets[i];
			FAssert(((int)uiCodeAddress) > -aAdressOffsets[i]);
			uiCodeAddress += aAdressOffsets[i];
			if (!unprotectPage(reinterpret_cast<LPVOID>(uiCodeAddress), sizeof(float)))
				return;
			*reinterpret_cast<float*>(uiCodeAddress) = fSize;
		}
	}

	bool testCodeLayout(int iAddressOffset = 0)
	{
		/*	This is the call to CvPlayer::getGlobeLayerColors:
			 004649A9	call dword ptr ds:[0BC1E64h] */
		byte aCodeBytes[] = { 0xFF, 0x15, 0x64, 0x1E, 0xBC, 0x00 };
		byte* pCodeLoc = reinterpret_cast<byte*>(0x004649A9 + iAddressOffset);
		for (int i = 0; i < ARRAYSIZE(aCodeBytes); i++)
		{
			if (aCodeBytes[i] != pCodeLoc[i])
			{
		#ifdef _DEBUG
			FAssertMsg(aCodeBytes[i] != 0xCC, "Interrupt found in native code. "
					/*	Remedy: Should probably keep breakpoints disabled
						until SelfMod is finished */
					"Debugger breakpoint?");
		#endif
				return false;
			}
		}
		return true; // Looks good, we don't worry.
	}
	
private:
	int m_iScreenHeight;
	struct PlotIndicatorSize
	{
		PlotIndicatorSize(float fOnScreen = 0, float fOffScreen = 0)
		:	onScreen(fOnScreen), offScreen(fOffScreen) {}
		// Overriding operator== for this nested thing would be a PITA
		bool equals(PlotIndicatorSizePatch::PlotIndicatorSize const& kOther)
		{	// Exact floating point comparison
			return (onScreen == kOther.onScreen &&
					offScreen == kOther.offScreen);
		}
		float onScreen, offScreen;
	};
};

} // (end of unnamed namespace)


void Civ4BeyondSwordMods::patchPlotIndicatorSize()
{
	int const iScreenHeight = GC.getGame().getScreenHeight();
	if (iScreenHeight <= 0)
	{
		FErrorMsg("Caller should've ensured that screen dims are set");
		return;
	}
	// (If we fail past here, there won't be a point in trying again.)
	m_bPlotIndicatorSizePatched = true;
	PlotIndicatorSizePatch patch(iScreenHeight);
	patch.apply();
}
