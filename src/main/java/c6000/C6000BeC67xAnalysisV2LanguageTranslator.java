// SPDX-License-Identifier: Apache-2.0
package c6000;

/** Migrates C6000:BE:32:c67x-analysis projects from language version 2 to 3 (128-bit context register). */
public class C6000BeC67xAnalysisV2LanguageTranslator extends C6000CompactHalfwordTranslation {
	public C6000BeC67xAnalysisV2LanguageTranslator() {
		super("C6000:BE:32:c67x-analysis", 2, 3);
	}
}
