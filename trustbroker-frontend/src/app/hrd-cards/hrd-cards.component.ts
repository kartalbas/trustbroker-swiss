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
import { ChangeDetectionStrategy, Component, DestroyRef, TemplateRef, ViewChild, effect, input } from '@angular/core';
import { IdpObject, IdpObjectWithNoticeClaimProviders, IdpObjects } from '../model/IdpObject';
import { environment } from '../../environments/environment';
import { ThemeService } from '../services/theme-service';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { IdpObjectService } from '../services/idp-object.service';
import { Dialog } from '@angular/cdk/dialog';
import { Overlay } from '@angular/cdk/overlay';
import { HrdSelectionService } from '../services/hrd-selection.service';
import { ClaimsProviderNoticeService } from '../services/claims-provider-notice.service';
import { ValidationService } from '../services/validation-service';

@Component({
	selector: 'app-hrd-cards',
	templateUrl: './hrd-cards.component.html',
	styleUrl: './hrd-cards.component.scss',
	changeDetection: ChangeDetectionStrategy.OnPush,
	standalone: false
})
export class HrdCardsComponent {
	apiBaseUrl: string = environment.apiUrl;

	idpObjects = input.required<IdpObjects>();
	theme$ = this.themeService.theme$;

	@ViewChild('disabledDialogContent') disabledDialogContentRef: TemplateRef<Element>;

	constructor(
		private readonly route: ActivatedRoute,
		private readonly router: Router,
		protected readonly themeService: ThemeService,
		private readonly destroyRef: DestroyRef,
		private readonly idpObjectService: IdpObjectService,
		private readonly dialog: Dialog,
		private readonly overlay: Overlay,
		private readonly hrdSelectionService: HrdSelectionService,
		private readonly claimsProviderNoticeService: ClaimsProviderNoticeService,
		private readonly validation: ValidationService
	) {
		effect(async () => {
			const tiles = this.idpObjects().tiles || [];
			if (tiles.length === 1 && !tiles[0].disabled) {
				await this.onCardClick(tiles[0]);
			} else {
				// disabled tiles are also displayed in help
				this.idpObjectService.addIdpObjects(tiles);
			}
		});
	}

	public async onCardClick(idpObject: IdpObject) {
		if (idpObject.noticeClaimsProviders && (idpObject.noticeMaxAgeSec === -1 || !this.claimsProviderNoticeService.hasCookieSet(idpObject))) {
			const noticeClaimProviders = this.idpObjects().tiles?.filter(({ name }) => idpObject.noticeClaimsProviders?.includes(name)) ?? [];
			const idpObjectWithNoticeClaimsProviders: IdpObjectWithNoticeClaimProviders = {
				...idpObject,
				noticeClaimProviders
			};

			await this.router.navigate(['claimsprovidernotice', idpObject.name, this.route.snapshot.params['issuer'], this.route.snapshot.params['authnRequestId']], {
				state: { idpObject: idpObjectWithNoticeClaimsProviders }
			});
			return;
		}

		const authnRequestId = this.validation.getValidParameter(this.route.snapshot.params, 'authnRequestId', ValidationService.ID, '');
		this.hrdSelectionService.selectIdp(authnRequestId, idpObject);
	}

	onOpenDialog(idpObject: IdpObject, element: Element, event: Event): void {
		event.stopPropagation(); // avoid the calling the idp represented by the button below
		if (event instanceof KeyboardEvent && event.key !== 'Enter') {
			return;
		}

		element.setAttribute('aria-expanded', 'true');
		const strategy = this.overlay
			.position()
			.flexibleConnectedTo(element)
			.withPositions([
				{ originX: 'start', originY: 'top', overlayX: 'start', overlayY: 'bottom', offsetY: 0 },
				{ originX: 'start', originY: 'bottom', overlayX: 'start', overlayY: 'top', offsetY: 0 }
			]);

		this.dialog.openDialogs.forEach(dialogRef => dialogRef.close());

		const dialogRef = this.dialog.open(this.disabledDialogContentRef, {
			minWidth: element.clientWidth,
			maxWidth: element.clientWidth,
			positionStrategy: strategy,
			data: {
				disabled: idpObject.disabled,
				title: idpObject.title,
				labeledById: element.id
			}
		});

		dialogRef.closed.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => element.setAttribute('aria-expanded', 'false'));
	}
}
