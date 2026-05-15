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
import { DestroyRef, Injectable, inject } from '@angular/core';
import { ApiService } from './api.service';
import { ValidationService } from './validation-service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { IdpObject } from '../model/IdpObject';

@Injectable({ providedIn: 'root' })
export class HrdSelectionService {
	private readonly apiService = inject(ApiService);
	private readonly destroyRef = inject(DestroyRef);
	private readonly router = inject(Router);
	private readonly validation = inject(ValidationService);

	public selectIdp(authnRequestId: string, { urn }: IdpObject): void {
		this.apiService
			.selectIdp(authnRequestId, urn)
			.pipe(takeUntilDestroyed(this.destroyRef))
			.subscribe({
				next: response => {
					const location = response.headers.get('location');
					if (location) {
						// writing the body of the redirect result to the document does not work
						window.location.href = location;
						return;
					}
					// document.write for error page does not work here
					const url = response.url!.replace(/^.*(\/failure\/.*$)/, '$1');
					if (url !== response.url) {
						void this.router.navigate([url]);
						return;
					}
					window.document.write(response.body!);
					if (document.forms.length > 0) {
						document.forms[0].submit();
					} else {
						// not a SAML form, e.g. AccessRequest
						// NOSONAR
						// console.info('[HrdCardsComponent] Do not have a form to submit');
					}
				},
				error: errorResponse => {
					console.error('an error occured', errorResponse);
				}
			});
	}
}
