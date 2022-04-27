
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1400f9300(longlong *param_1,undefined8 param_2,undefined8 param_3,longlong param_4)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  HANDLE pvVar4;
  undefined8 *puVar5;
  ulonglong **ppuVar6;
  HMODULE pHVar7;
  ulonglong uVar8;
  longlong *plVar9;
  float *pfVar10;
  undefined8 *puVar11;
  char *pcVar12;
  __crt_locale_pointers *p_Var13;
  undefined8 uVar14;
  undefined auStack136 [32];
  undefined8 *local_68;
  undefined8 local_60;
  ulonglong **local_58;
  undefined local_50;
  undefined8 local_40;
  undefined8 local_38;
  ulonglong *local_30 [4];
  ulonglong local_10;
  
  local_60 = 0xfffffffffffffffe;
  local_10 = DAT_140b3e150 ^ (ulonglong)auStack136;
  FUN_1402d14a0();
  FUN_1402d4fa0((longlong)(param_1 + 0x1ce));
  uVar14 = FUN_140042400(0);
  FUN_14002bd60(uVar14,60.0);
  iVar2 = FUN_1400d45e0();
  if ((iVar2 == 2) || (iVar2 == 4)) {
    cVar1 = '\0';
LAB_1400f93ce:
    FUN_1400e6920(cVar1);
  }
  else {
    if (iVar2 == 6) {
      iVar2 = FUN_1400e6460();
      if (((iVar2 != 0x400) || (iVar2 = FUN_1400e6480(), iVar2 != 0x300)) &&
         ((iVar2 = FUN_1400e6480(), iVar2 != 0x400 || (iVar2 = FUN_1400e6460(), iVar2 != 0x300))))
      goto LAB_1400f9374;
    }
    else if (iVar2 != 7) {
LAB_1400f9374:
      cVar1 = '\x01';
      goto LAB_1400f93ce;
    }
    FUN_1400e6920('\0');
    uVar3 = FUN_1400efc30();
    iVar2 = FUN_1400efc20();
    FUN_1400e69b0(iVar2,uVar3,1);
  }
  thunk_FUN_1400d9920(2000);
  if (*(char *)((longlong)param_1 + 0x24a) != '\0') goto LAB_1400f9709;
  pvVar4 = OpenMutexA(0x1f0001,0,"Growtopia");
  if ((pvVar4 == (HANDLE)0x0) &&
     (pvVar4 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,"Growtopia"), pvVar4 != (HANDLE)0x0)) {
    pcVar12 = "Growtopia";
    uVar14 = 0;
    pvVar4 = OpenMutexA(0x1f0001,0,"Growtopia");
    if (pvVar4 != (HANDLE)0x0) {
      uVar14 = FUN_14002ac60((longlong)param_1,uVar14,pcVar12,param_4);
      if ((char)uVar14 != '\0') {
        puVar5 = (undefined8 *)FUN_1400ee330((ulonglong **)&local_50);
        if (0xf < (ulonglong)puVar5[3]) {
          puVar5 = (undefined8 *)*puVar5;
        }
        FUN_1400efff0((longlong)"Save path is %s",(__crt_locale_pointers *)puVar5,(longlong)pcVar12,
                      param_4);
        FUN_14001dae0((ulonglong **)&local_50);
        local_58 = local_30;
        ppuVar6 = (ulonglong **)FUN_1400ee330(local_30);
        local_38 = 0xf;
        plVar9 = (longlong *)0x0;
        local_40 = 0;
        local_50 = 0;
        FUN_14001de70((ulonglong **)&local_50,(ulonglong **)&PTR_1408ca3a0,(ulonglong *)0x0);
        FUN_1400ed470((ulonglong **)&local_50,ppuVar6);
        ppuVar6 = (ulonglong **)FUN_1400ee330(local_30);
        FUN_1400eecc0(ppuVar6);
        FUN_14001dae0(local_30);
        *(undefined4 *)((longlong)param_1 + 0x44c) = 2;
        *(undefined4 *)((longlong)param_1 + 0x5c4) = 2;
        pHVar7 = GetModuleHandleA((LPCSTR)0x0);
        if (pHVar7 != (HMODULE)0x0) {
          uVar8 = FUN_1400e4380(30000);
          _DAT_140b6c188 = (int)uVar8;
          uVar8 = FUN_1400e33e0((byte *)(pHVar7 + (*(uint *)((longlong)&pHVar7[0xb].unused +
                                                            (longlong)pHVar7[0xf].unused) >> 2)),
                                *(uint *)((longlong)&pHVar7[7].unused + (longlong)pHVar7[0xf].unused
                                         ));
          DAT_140b6c18c = (int)uVar8 + _DAT_140b6c188;
        }
        cVar1 = FUN_1400e64b0();
        local_38 = 0xf;
        local_40 = 0;
        local_50 = 0;
        if (cVar1 == '\0') {
          FUN_14001de70((ulonglong **)&local_50,(ulonglong **)"interface/font_century_gothic.rtfont"
                        ,(ulonglong *)&DAT_00000024);
          cVar1 = FUN_1400968c0((ulonglong)(param_1 + 0x6b),(ulonglong **)&local_50,1,param_4);
          if (cVar1 == '\0') goto LAB_1400f9709;
          local_38 = 0xf;
          local_40 = 0;
          local_50 = 0;
          uVar14 = 0;
          FUN_14001de70((ulonglong **)&local_50,
                        (ulonglong **)"interface/font_century_gothic_big.rtfont",
                        (ulonglong *)&DAT_00000028);
          p_Var13 = (__crt_locale_pointers *)CONCAT71((int7)((ulonglong)uVar14 >> 8),1);
          cVar1 = FUN_1400968c0((ulonglong)(param_1 + 0x9a),(ulonglong **)&local_50,1,param_4);
        }
        else {
          FUN_14001de70((ulonglong **)&local_50,
                        (ulonglong **)"interface/font_century_gothicx2.rtfont",(ulonglong *)0x26);
          cVar1 = FUN_1400968c0((ulonglong)(param_1 + 0x6b),(ulonglong **)&local_50,1,param_4);
          if (cVar1 == '\0') goto LAB_1400f9709;
          local_38 = 0xf;
          local_40 = 0;
          local_50 = 0;
          uVar14 = 0;
          FUN_14001de70((ulonglong **)&local_50,
                        (ulonglong **)"interface/font_century_gothic_bigx2.rtfont",(ulonglong *)0x2a
                       );
          p_Var13 = (__crt_locale_pointers *)CONCAT71((int7)((ulonglong)uVar14 >> 8),1);
          cVar1 = FUN_1400968c0((ulonglong)(param_1 + 0x9a),(ulonglong **)&local_50,1,param_4);
        }
        if (cVar1 != '\0') {
          iVar2 = FUN_1400e43b0(0x143,0x9f6);
          DAT_140b35654 = (undefined2)iVar2;
          (**(code **)(*param_1 + 0x48))(param_1);
          FUN_1400fb7a0((longlong)param_1);
          local_68 = (undefined8 *)operator_new(0x60);
          if (local_68 != (undefined8 *)0x0) {
            plVar9 = FUN_14009cd60(local_68);
          }
          FUN_14009a830((longlong)&DAT_140b6c1d8,plVar9,p_Var13,param_4);
          FUN_1403ff420();
          pfVar10 = FUN_1400e6430((float *)&local_68);
          puVar5 = (undefined8 *)FUN_1400e2100((ulonglong **)&local_50,pfVar10);
          puVar11 = (undefined8 *)FUN_1400ee000(local_30);
          if (0xf < (ulonglong)puVar5[3]) {
            puVar5 = (undefined8 *)*puVar5;
          }
          if (0xf < (ulonglong)puVar11[3]) {
            puVar11 = (undefined8 *)*puVar11;
          }
          FUN_1400efff0((longlong)"Current locale is %s, screen size is %s",
                        (__crt_locale_pointers *)puVar11,(longlong)puVar5,param_4);
          FUN_14001dae0(local_30);
          FUN_14001dae0((ulonglong **)&local_50);
          FUN_1403fed50();
        }
      }
      goto LAB_1400f9709;
    }
  }
  MessageBoxA((HWND)0x0,"An instance of Growtopia is already running!  Go play that one.",
              "Growtopia",0);
LAB_1400f9709:
  FUN_1407ef730(local_10 ^ (ulonglong)auStack136);
  return;
}

