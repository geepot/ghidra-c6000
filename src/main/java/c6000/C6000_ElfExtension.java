/* ###
 * Copyright 2026 ghidra-c6000 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c6000;

import java.util.regex.Pattern;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;
import ghidra.program.model.address.Address;
import ghidra.util.exception.InvalidInputException;

/** TI C6000 ELF: compiler branch and return labels are STT_FUNC, so load them as code labels, not functions. */
public class C6000_ElfExtension extends ElfExtension {
	private static final Pattern COMPILER_LABEL = Pattern.compile("\\$C\\$R?L\\d+");

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_TI_C6000;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"C6000".equals(elfLoadHelper.getProgram().getLanguage().getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_C6000";
	}

	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {
		if (isExternal || !elfSymbol.isLocal() || elfSymbol.getType() != ElfSymbol.STT_FUNC ||
			elfSymbol.getSize() != 0 || !COMPILER_LABEL.matcher(elfSymbol.getNameAsString()).matches()) {
			return address;
		}
		try {
			elfLoadHelper.createSymbol(address, elfSymbol.getNameAsString(), false, false, null);
		}
		catch (InvalidInputException e) {
			return address;
		}
		elfLoadHelper.markAsCode(address);
		elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
		return null;
	}
}
