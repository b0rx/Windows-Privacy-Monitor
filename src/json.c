// © 2025 B0rx. All rights reserved.
// Last Change: 11.11.2025

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "json.h"

BOOL IsInList(const char* name, char** list, int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(list[i], name) == 0) return TRUE;
    }
    return FALSE;
}

void AddToList(const char* name, char*** plist, int* pcount) {
    if (IsInList(name, *plist, *pcount)) return;
    char* newname = (char*)malloc(strlen(name) + 1);
    if (!newname) return;
    strcpy(newname, name);
    *plist = (char**)realloc(*plist, (*pcount + 1) * sizeof(char*));
    if (*plist) {
        (*plist)[*pcount] = newname;
        (*pcount)++;
    } else {
        free(newname);
    }
}

void RemoveFromList(int index, char*** plist, int* pcount) {
    if (index < 0 || index >= *pcount) return;
    free((*plist)[index]);
    for (int i = index; i < *pcount - 1; i++) {
        (*plist)[i] = (*plist)[i + 1];
    }
    *plist = (char**)realloc(*plist, (*pcount - 1) * sizeof(char*));
    if (*pcount > 0) (*pcount)--;
}

void SaveLists(const char* filename, char** blacklist, int blacklistCount, 
               char** whitelist, int whitelistCount) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    fprintf(f, "{\n  \"blacklist\": [\n");
    for (int i = 0; i < blacklistCount; i++) {
        fprintf(f, "    \"%s\"%s\n", blacklist[i], (i < blacklistCount - 1) ? "," : "");
    }
    fprintf(f, "  ],\n  \"whitelist\": [\n");
    for (int i = 0; i < whitelistCount; i++) {
        fprintf(f, "    \"%s\"%s\n", whitelist[i], (i < whitelistCount - 1) ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
}

void LoadLists(const char* filename, char*** pBlacklist, int* pBlacklistCount,
               char*** pWhitelist, int* pWhitelistCount) {
    if (*pBlacklist) {
        for (int i = 0; i < *pBlacklistCount; i++) free((*pBlacklist)[i]);
        free(*pBlacklist);
    }
    *pBlacklist = NULL;
    *pBlacklistCount = 0;
    if (*pWhitelist) {
        for (int i = 0; i < *pWhitelistCount; i++) free((*pWhitelist)[i]);
        free(*pWhitelist);
    }
    *pWhitelist = NULL;
    *pWhitelistCount = 0;

    FILE* f = fopen(filename, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) {
        fclose(f);
        return;
    }
    char* buf = (char*)malloc(len + 1);
    if (!buf) {
        fclose(f);
        return;
    }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);

    char* pos = strstr(buf, "\"blacklist\"");
    if (pos) {
        pos += 10;
        while (*pos && *pos != ':') pos++;
        if (*pos == ':') pos++;
        while (isspace(*pos)) pos++;
        if (*pos == '[') pos++;
        while (isspace(*pos)) pos++;
        char** tempBlack = NULL;
        int countBlack = 0;
        while (*pos != ']' && pos - buf < len) {
            if (*pos == '"') {
                pos++;
                char* start = pos;
                while (*pos && *pos != '"') pos++;
                if (*pos == '"') {
                    char saved = *pos;
                    *pos = '\0';
                    char* name = (char*)malloc(strlen(start) + 1);
                    if (name) {
                        strcpy(name, start);
                        tempBlack = (char**)realloc(tempBlack, (countBlack + 1) * sizeof(char*));
                        if (tempBlack) {
                            tempBlack[countBlack++] = name;
                        } else {
                            free(name);
                        }
                    }
                    *pos = saved;
                    pos++;
                }
            } else {
                pos++;
            }
            while (pos - buf < len && isspace(*pos)) pos++;
            if (pos - buf < len && *pos == ',') pos++;
            while (pos - buf < len && isspace(*pos)) pos++;
        }
        *pBlacklist = tempBlack;
        *pBlacklistCount = countBlack;
    }

    pos = strstr(buf, "\"whitelist\"");
    if (pos) {
        pos += 11;
        while (*pos && *pos != ':') pos++;
        if (*pos == ':') pos++;
        while (isspace(*pos)) pos++;
        if (*pos == '[') pos++;
        while (isspace(*pos)) pos++;
        char** tempWhite = NULL;
        int countWhite = 0;
        while (*pos != ']' && pos - buf < len) {
            if (*pos == '"') {
                pos++;
                char* start = pos;
                while (*pos && *pos != '"') pos++;
                if (*pos == '"') {
                    char saved = *pos;
                    *pos = '\0';
                    char* name = (char*)malloc(strlen(start) + 1);
                    if (name) {
                        strcpy(name, start);
                        tempWhite = (char**)realloc(tempWhite, (countWhite + 1) * sizeof(char*));
                        if (tempWhite) {
                            tempWhite[countWhite++] = name;
                        } else {
                            free(name);
                        }
                    }
                    *pos = saved;
                    pos++;
                }
            } else {
                pos++;
            }
            while (pos - buf < len && isspace(*pos)) pos++;
            if (pos - buf < len && *pos == ',') pos++;
            while (pos - buf < len && isspace(*pos)) pos++;
        }
        *pWhitelist = tempWhite;
        *pWhitelistCount = countWhite;
    }

    free(buf);
}
