#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void main()
{
	char* c[]={"JD","Skew1","GBG","Data",NULL};
	char box[16]={0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };
	char key[33]={0};
	int pos=0;
	for(int i=0;c[i]!=NULL;i++)
	{
		char cc[80]="SYSTEM\\CurrentControlSet\\Control\\Lsa\\\0\0\0\0\0\0\0\0\0\0\0\0";
		HKEY hkey=0;
		RegOpenKeyEx(HKEY_LOCAL_MACHINE,strcat(cc,c[i]),0,0x19,&hkey);
		char tmp[16]={0};
		unsigned long len=16;
		DWORD d=0;
		RegQueryInfoKey(hkey,tmp,&len,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0);
		for(int ii=0;ii<8;ii++)
		{
			key[pos]=tmp[ii];
			pos++;
		}
		RegCloseKey(hkey);
	}
	BYTE tmp[16]={0};
	BYTE tmp2[16]={0};
	for(i=0;i<16;i++)
	{
		int pos=i*2+2;
		char c=key[pos];
		key[pos]='\0';
		tmp[i]=strtol(key+i*2,NULL,16);
		key[pos]=c;
	}
	for(i=0;i<16;i++)
	{
		tmp2[i]=tmp[box[i]];
	}
	for(i=0;i<16;i++)
	{
		printf("%02x",tmp2[i]);
	}
	printf("\n");
}