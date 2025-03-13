# Tamper - Lab Report

The (hexadecimal) number printed by your debug check: `0x67340941`
The (hexadecimal) hash of the string "/bin/sh": `0xc44fb8df`

## 1. Preparation

### 1.1 Add debug check

```diff
--- check1.c    2023-11-27 11:39:28.599059924 +0100
+++ check1_prepared.c   2023-11-27 18:49:18.239846981 +0100
@@ -6,12 +6,12 @@
 typedef char* caddr_t;
 typedef uint32_t* waddr_t;
 
-#define EXPECTED 0
+#define EXPECTED 0x23275028
 
 void BEGIN() { }
 int is_being_debugged()
 {
-    int s = 0 /* TODO */;
+    int s = ptrace(PTRACE_TRACEME);
     if (s == -1) {
         printf("Program is being debugged: 0x%08X\n", 0x67340941);
         *((int*)NULL) = 42;
```

## 2. Attack

### 2.1 Change to is_being_debugged

```diff
--- check1_prepared.c   2023-11-27 11:59:32.552408625 +0100
+++ check1_debug.c      2023-11-27 14:08:44.255675521 +0100
@@ -12,7 +12,7 @@
 int is_being_debugged()
 {
     int s = ptrace(PTRACE_TRACEME);
-    if (s == -1) {
+    if (s == -2) {
         printf("Program is being debugged: 0x%08X\n", 0x67340941);
         *((int*)NULL) = 42;
     }
```

Yes, the check routine catches the hack.

### 2.2 Change to hash

```diff
--- check1_debug.c      2023-11-27 14:08:44.255675521 +0100
+++ check1_hash.c       2023-11-27 14:19:08.977570076 +0100
@@ -26,7 +26,7 @@
         addr++;
         h ^= *addr;
     }
-    return h;
+    return EXPECTED;
 }
 
 void check()
```

### 2.3 Change to check

```diff
--- check1_debug.c      2023-11-27 14:08:44.255675521 +0100
+++ check1_check.c      2023-11-27 14:22:31.902185491 +0100
@@ -32,7 +32,7 @@
 void check()
 {
     uint32_t h = hash((waddr_t)BEGIN, (waddr_t)END);
-    if (h != EXPECTED) {
+    if (h == EXPECTED) {
         puts("is_being_debugged() has been modified!\n");
         *((int*)NULL) = 9;
     }
```

## 3. Fix

### 3.1 Repair after crack

```diff
--- repair.c    2023-11-27 11:40:08.182990503 +0100
+++ repair_prepared.c   2023-11-27 17:09:07.592004908 +0100
@@ -8,13 +8,13 @@
 typedef char* caddr_t;
 typedef uint32_t* waddr_t;
 
-#define EXPECTED 0x0
-uint32_t COPY[] = {};
+#define EXPECTED 0x4dd62388
+uint32_t COPY[] = {0xfa1e0ff3,0xe5894855,0xfc35d90,0x441f,0xfa1e0ff3,0xe5894855,0x10ec8348,0xbf,0xb800,0x95e80000,0x89fffffe,0x7d83fc45,0x2475fffc,0x340941be,0x58d4867,0xd98,0xb8c78948,0x0,0xfffe63e8,0xb8ff,0xc70000,0x2a,0xfc3c990,0x441f,0xfa1e0ff3,0xe5894855,0xe87d8948,0xe0758948,0xe8458b48,0xdf35008b,0x89aa4ea9,0xeebfc45,0xe8458348,0x458b4804,0x31008be8,0x8b48fc45,0x3b48e845,0xe872e045,0x5dfc458b,0x1f0fc3};
 
 void BEGIN() { }
 int is_being_debugged()
 {
-    int s = 0 /* TODO */;
+    int s = ptrace(PTRACE_TRACEME);
     if (s == -1) {
         printf("Program is being debugged: 0x%08X\n", 0x67340941);
         *((int*)NULL) = 42;
@@ -38,7 +38,11 @@
     uint32_t h = hash((waddr_t)BEGIN, (waddr_t)END);
     if (h != EXPECTED) {
         puts("is_being_debugged() has been modified!\n");
-        *((int*)NULL) = 9;
+        waddr_t address = (waddr_t)BEGIN;
+        for(size_t i = 0; i <sizeof(COPY) / sizeof(uint32_t);i++) {
+            *address = COPY[i];
+            address++;
+        }
     }
 }
```

### 3.2 Change to is_being_debugged

```diff
--- repair_prepared.c   2023-11-27 17:09:07.592004908 +0100
+++ repair_debug.c      2023-11-27 17:11:02.736009252 +0100
@@ -15,7 +15,7 @@
 int is_being_debugged()
 {
     int s = ptrace(PTRACE_TRACEME);
-    if (s == -1) {
+    if (s == -2) {
         printf("Program is being debugged: 0x%08X\n", 0x67340941);
         *((int*)NULL) = 42;
     }
```

The function works, as if it wasn't modified at all.

## 4. Check the Check

### 4.1 Add check2()

```diff
--- check2.c    2023-11-27 11:40:02.059000292 +0100
+++ check2_prepared.c   2023-11-27 18:19:41.830636146 +0100
@@ -6,13 +6,13 @@
 typedef char* caddr_t;
 typedef uint32_t* waddr_t;
 
-#define EXPECTED1 0
-#define EXPECTED2 0
+#define EXPECTED1 0x1dd6d008
+#define EXPECTED2 0x1b338f12
 
 void BEGIN1() { }
 int is_being_debugged()
 {
-    int s = 0 /* TODO */;
+    int s = ptrace(PTRACE_TRACEME);
     if (s == -1) {
         printf("Program is being debugged: 0x%08X\n", 0x67340941);
         *((int*)NULL) = 42;
@@ -44,6 +44,11 @@
 
 void check2()
 {
+    uint32_t h = hash((waddr_t)BEGIN2, (waddr_t)END2);
+    if (h != EXPECTED2) {
+        puts("check() has been modified!\n");
+        *((int*)NULL) = 21;
+    }
 }
 
 void dump()
```

### 4.2 Compile, set defines, compile, set defines

Since the expected hash value changes the function's hash multiple compilation cycles are needed to get the correct hash value.

### 4.3 Tamper with check

```diff
--- check2_prepared.c   2023-11-27 19:04:32.702371261 +0100
+++ check2_check.c      2023-11-27 19:19:47.674062163 +0100
@@ -35,7 +35,7 @@
 void check()
 {
     uint32_t h = hash((waddr_t)BEGIN1, (waddr_t)END1);
-    if (h != EXPECTED1) {
+    if (h == EXPECTED1) {
         puts("is_being_debugged() has been modified!\n");
         *((int*)NULL) = 9;
     }
```

The original function is seen as faulty, but if there were changes to the debugging function, the check2 function would still cause a segmentation fault.

### 4.4 Further tampering

If check and check2 both were to be tampered with, one could freely modify is_being_debugged, without causing segmentation faults.