/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kie.bc.client.home;

import org.jboss.errai.ui.client.local.spi.TranslationService;
import org.kie.bc.client.resources.i18n.Constants;
import org.kie.workbench.common.profile.api.preferences.ProfilePreferences;
import org.kie.workbench.common.screens.home.client.widgets.shortcut.utils.ShortcutHelper;
import org.kie.workbench.common.screens.home.model.HomeModel;
import org.kie.workbench.common.screens.home.model.HomeModelProvider;
import org.kie.workbench.common.screens.home.model.HomeShortcut;
import org.kie.workbench.common.screens.home.model.HomeShortcutLink;
import org.kie.workbench.common.screens.home.model.ModelUtils;
import org.uberfire.client.mvp.PlaceManager;

import static org.kie.workbench.common.workbench.client.PerspectiveIds.PROVISIONING;
import static org.kie.workbench.common.workbench.client.PerspectiveIds.SERVER_MANAGEMENT;
import static org.uberfire.workbench.model.ActivityResourceType.PERSPECTIVE;

public abstract class AbstractHomeProducer implements HomeModelProvider {

    protected PlaceManager placeManager;
    protected TranslationService translationService;
    protected ProfilePreferences profilePreferences;
    private ShortcutHelper shortcutHelper;

    public AbstractHomeProducer() {
        //CDI proxy
    }

    public AbstractHomeProducer(final PlaceManager placeManager,
                                final TranslationService translationService,
                                final ShortcutHelper shortcutHelper) {
        this.placeManager = placeManager;
        this.translationService = translationService;
        this.shortcutHelper = shortcutHelper;
    }

    public HomeModel get(ProfilePreferences preferences) {
        this.profilePreferences = preferences;
        final HomeModel model = new HomeModel(translationService.format(Constants.Heading),
                                              translationService.format(Constants.SubHeading),
                                              "images/community_home_bg.jpg");

        addProfileFullShortcuts(model);

        return model;
    }

    private void addProfileFullShortcuts(final HomeModel model) {
        model.addShortcut(createDesignShortcut());
        model.addShortcut(createDeployShortcut());
    }

    protected HomeShortcut createDeployShortcut() {
        final HomeShortcutLink deployments = new HomeShortcutLink(translationService.format(Constants.Provisioning),
                                                                  PROVISIONING);
        final HomeShortcutLink servers = new HomeShortcutLink(translationService.format(Constants.Servers),
                                                              SERVER_MANAGEMENT);
        final boolean isDeploymentsAuthorized = shortcutHelper.authorize(deployments.getPerspectiveIdentifier());

        final HomeShortcut deploy = ModelUtils.makeShortcut("fa fa-gears",
                                                            translationService.format(Constants.Deploy),
                                                            getDeployDescription(isDeploymentsAuthorized),
                                                            () -> placeManager.goTo(SERVER_MANAGEMENT),
                                                            SERVER_MANAGEMENT,
                                                            PERSPECTIVE);
        if (isDeploymentsAuthorized) {
            deploy.addLink(deployments);
        }
        deploy.addLink(servers);

        return deploy;
    }

    private String getDeployDescription(final boolean isDeploymentsAuthorized) {
        if (isDeploymentsAuthorized) {
            return translationService.format(Constants.DeployDescription2);
        }
        return translationService.format(Constants.DeployDescription1);
    }

    protected String getDesignDescription() {
        return translationService.format(Constants.DesignDescription);
    }

    protected abstract HomeShortcut createDesignShortcut();
}
