//===-- tsan_suppressions.h -------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
//===----------------------------------------------------------------------===//
#ifndef TSAN_SUPPRESSIONS_H
#define TSAN_SUPPRESSIONS_H

#include "tsan_report.h"

namespace __tsan {

// Exposed for testing.
enum SuppressionType {
  SuppressionNone,
  SuppressionRace,
  SuppressionMutex,
  SuppressionThread,
  SuppressionSignal
};

struct Suppression {
  Suppression *next;
  SuppressionType type;
  char *templ;
  int hit_count;
};

void InitializeSuppressions();
void FinalizeSuppressions();
void PrintMatchedSuppressions();
uptr IsSuppressed(ReportType typ, const ReportStack *stack, Suppression **sp);
uptr IsSuppressed(ReportType typ, const ReportLocation *loc, Suppression **sp);
Suppression *SuppressionParse(Suppression *head, const char* supp);
bool SuppressionMatch(char *templ, const char *str);

}  // namespace __tsan

#endif  // TSAN_SUPPRESSIONS_H
