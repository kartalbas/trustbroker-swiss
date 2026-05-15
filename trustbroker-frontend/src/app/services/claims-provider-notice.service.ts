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
import { Injectable, inject } from '@angular/core';
import { CookieService } from './cookie-service';
import { IdpObject } from '../model/IdpObject';
import { Configuration } from '../model/Configuration';
import { ApiService } from './api.service';

@Injectable({ providedIn: 'root' })
export class ClaimsProviderNoticeService {
	private readonly cookieService = inject(CookieService);
	private readonly apiService = inject(ApiService);
	private readonly config: Configuration = this.apiService.getConfiguration();

	public hasCookieSet(idpObject: IdpObject): boolean {
		return this.cookieService.check(this.computeCookieName(idpObject));
	}

	public setCookie(idpObject: IdpObject): void {
		this.cookieService.set(
			{
				...this.config.claimsProviderNoticeCookie,
				name: this.computeCookieName(idpObject)
			},
			'read',
			idpObject.noticeMaxAgeSec ? new Date(Date.now() + idpObject.noticeMaxAgeSec * 1000).toISOString() : undefined
		);
	}

	public deleteCookie(idpObject: IdpObject): void {
		this.cookieService.delete(this.computeCookieName(idpObject), this.config.claimsProviderNoticeCookie.path);
	}

	private computeCookieName({ name }: IdpObject): string {
		return `${this.config.claimsProviderNoticeCookie.name}-${name}`;
	}
}
