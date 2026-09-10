/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var App = require('app');

/**
 * Compatibility catalog for the legacy Ember administration experience.
 * Deployment and upgrade workflows remain owned by Stack and Versions.
 */
App.MainAdminManagementPacksController = Em.Controller.extend({
  name: 'mainAdminManagementPacksController',

  registries: [],
  catalog: [],
  mpacks: [],
  dataIsLoaded: false,
  loadError: null,
  operationError: null,
  operationInProgress: false,
  directUri: '',
  pendingRequests: 0,

  canManage: function () {
    return App.isAuthorized('AMBARI.MANAGE_STACK_VERSIONS');
  }.property(''),

  canMutate: function () {
    return this.get('canManage')
      && !App.get('upgradeInProgress')
      && !App.get('upgradeHolding')
      && !App.get('router.mainController.isWorking');
  }.property('canManage', 'App.upgradeInProgress', 'App.upgradeHolding'),

  load: function () {
    this.setProperties({
      dataIsLoaded: false,
      loadError: null,
      operationError: null,
      pendingRequests: 2
    });
    App.ajax.send({
      name: 'admin.mpacks.registries',
      sender: this,
      success: 'loadRegistriesSuccess',
      error: 'loadErrorCallback'
    });
    App.ajax.send({
      name: 'admin.mpacks.all',
      sender: this,
      success: 'loadMpacksSuccess',
      error: 'loadErrorCallback'
    });
  },

  loadRegistriesSuccess: function (data) {
    var registries = [];
    var catalog = [];
    (data.items || []).forEach(function (item) {
      var info = item.RegistryInfo || {};
      var registry = Em.Object.create({
        id: info.registry_id,
        name: info.registry_name,
        type: info.registry_type,
        uri: info.registry_uri
      });
      registries.push(registry);
      (item.mpacks || []).forEach(function (mpackItem) {
        var mpack = mpackItem.RegistryMpackInfo || {};
        (mpackItem.versions || []).forEach(function (versionItem) {
          var version = versionItem.RegistryMpackVersionInfo || {};
          catalog.push(Em.Object.create({
            registryId: info.registry_id,
            registryName: info.registry_name,
            name: version.mpack_name || mpack.mpack_name,
            displayName: mpack.mpack_display_name || mpack.mpack_name,
            version: version.mpack_version,
            description: version.mpack_description || mpack.mpack_description,
            uri: version.mpack_uri,
            dependencies: version.mpack_dependencies || []
          }));
        });
      });
    });
    this.set('registries', registries);
    this.set('catalog', catalog.sort(function (left, right) {
      return String(left.get('name')).localeCompare(String(right.get('name')))
        || String(left.get('version')).localeCompare(String(right.get('version')));
    }));
    this.finishLoad();
  },

  loadMpacksSuccess: function (data) {
    var mpacks = (data.items || []).map(function (item) {
      var info = item.MpackInfo || {};
      return Em.Object.create({
        id: info.id,
        name: info.mpack_name,
        displayName: info.mpack_display_name || info.mpack_name,
        version: info.mpack_version,
        uri: info.mpack_uri,
        registryId: info.registry_id
      });
    });
    this.set('mpacks', mpacks);
    this.finishLoad();
  },

  finishLoad: function () {
    var pending = this.get('pendingRequests') - 1;
    this.set('pendingRequests', pending);
    if (pending <= 0) {
      this.set('dataIsLoaded', true);
    }
  },

  loadErrorCallback: function (jqXHR, textStatus, errorThrown) {
    var message = (jqXHR && jqXHR.responseJSON && jqXHR.responseJSON.message)
      || (jqXHR && jqXHR.responseText)
      || errorThrown
      || Em.I18n.t('admin.managementPacks.loadError');
    this.set('loadError', message);
    this.finishLoad();
  },

  registerUri: function () {
    var uri = String(this.get('directUri') || '').trim();
    if (!uri || !this.get('canMutate')) {
      return;
    }
    this.setProperties({ operationInProgress: true, operationError: null });
    App.ajax.send({
      name: 'admin.mpacks.register.uri',
      sender: this,
      data: { mpackUri: uri },
      success: 'registerUriSuccess',
      error: 'operationErrorCallback'
    });
  },

  registerUriSuccess: function () {
    this.setProperties({ directUri: '', operationInProgress: false });
    this.load();
  },

  registerCatalogItem: function (item) {
    if (!item || !this.get('canMutate')) {
      return;
    }
    var self = this;
    App.showConfirmationPopup(function () {
      self.setProperties({ operationInProgress: true, operationError: null });
      App.ajax.send({
        name: 'admin.mpacks.register.registry',
        sender: self,
        data: {
          registryId: item.get('registryId'),
          mpackName: item.get('name'),
          mpackVersion: item.get('version')
        },
        success: 'registerCatalogSuccess',
        error: 'operationErrorCallback'
      });
    }, 'Register ' + item.get('name') + ' ' + item.get('version') + '?');
  },

  registerCatalogSuccess: function () {
    this.set('operationInProgress', false);
    this.load();
  },

  removeMpack: function (mpack) {
    if (!mpack || !this.get('canMutate')) {
      return;
    }
    var self = this;
    App.showConfirmationPopup(function () {
      self.setProperties({ operationInProgress: true, operationError: null });
      App.ajax.send({
        name: 'admin.mpacks.remove',
        sender: self,
        data: { mpackId: mpack.get('id') },
        success: 'removeMpackSuccess',
        error: 'operationErrorCallback'
      });
    }, 'Remove ' + mpack.get('name') + ' ' + mpack.get('version') + '?');
  },

  removeMpackSuccess: function () {
    this.set('operationInProgress', false);
    this.load();
  },

  operationErrorCallback: function (jqXHR, textStatus, errorThrown) {
    var message = (jqXHR && jqXHR.responseJSON && jqXHR.responseJSON.message)
      || (jqXHR && jqXHR.responseText)
      || errorThrown
      || Em.I18n.t('admin.managementPacks.operationError');
    this.setProperties({ operationInProgress: false, operationError: message });
  }
});
