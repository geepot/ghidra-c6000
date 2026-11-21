// SPDX-License-Identifier: Apache-2.0
package c6000;

/** Migrates C6000:BE:32:default projects from language version 2 to 3 (128-bit context register). */
public class C6000BeDefaultV2LanguageTranslator extends C6000CompactHalfwordTranslation {
	public C6000BeDefaultV2LanguageTranslator() {
		super("C6000:BE:32:default", 2, 3);
	}
}
