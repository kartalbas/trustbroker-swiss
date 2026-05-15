/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */
import { Pipe, PipeTransform, inject } from '@angular/core';
import { SafeMarkupPipe } from './safe-markup.pipe';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Pipe({
	name: 'safeMarkup',
	standalone: true
})
export class SafeMarkupStandalonePipe implements PipeTransform {
	private readonly sanitizer = inject(DomSanitizer);
	private readonly safeMarkupPipe = new SafeMarkupPipe(this.sanitizer);

	transform(text: string | null): SafeHtml {
		return this.safeMarkupPipe.transform(text);
	}
}
