#pragma once

/**
 * @brief globally shows whether the anti-ransomware is enabled or not 
 * 
 */
BOOLEAN g_SystemMonIsEnabled = FALSE;

/**
 * @brief List entry to hold the list of files that 
 * are modified or deleted by all processes 
 * 
 */
LIST_ENTRY g_FileTraceList;

/**
 * @brief Maximum Files Allowed to be Modified
 * 
 */
UINT32 g_MaximumAllowed = 10;

/**
 * @brief Extensions buffer
 * 
 */
UINT64 g_ExtensionBuffers = NULL;

/**
 * @brief Is Extensions buffer initialized
 * 
 */
BOOLEAN g_IsExtensionBuffersInitialized = FALSE;

/**
 * @brief Is Extensions buffer initialized
 * 
 */
BOOLEAN g_IsPrimaryDiskAdded = FALSE;

/**
 * @brief Extensions buffer
 * 
 */
UINT64 g_PrimaryDiskBuffer = NULL;
