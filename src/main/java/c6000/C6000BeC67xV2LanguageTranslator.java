// SPDX-License-Identifier: Apache-2.0
package c6000;

/** Migrates C6000:BE:32:c67x projects from language version 2 to 3 (128-bit context register). */
public class C6000BeC67xV2LanguageTranslator extends C6000CompactHalfwordTranslation {
	public C6000BeC67xV2LanguageTranslator() {
		super("C6000:BE:32:c67x", 2, 3);
	}
}
