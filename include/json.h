// © 2025 B0rx. All rights reserved.
// Last Change: 11.11.2025

#ifndef JSON_H
#define JSON_H

BOOL IsInList(const char* name, char** list, int count);

void AddToList(const char* name, char*** plist, int* pcount);

void RemoveFromList(int index, char*** plist, int* pcount);

void SaveLists(const char* filename, char** blacklist, int blacklistCount, 
               char** whitelist, int whitelistCount);

void LoadLists(const char* filename, char*** pBlacklist, int* pBlacklistCount,
               char*** pWhitelist, int* pWhitelistCount);

#endif // JSON_H
