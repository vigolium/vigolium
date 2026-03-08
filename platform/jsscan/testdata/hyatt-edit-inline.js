var urlSite= window.location.href;
var moduleName = 'minisites';

if(urlSite.indexOf("brandexperience") !== -1){
	moduleName = 'brandexpirence';
} 

(function() {
  'use strict';

  angular.module(moduleName, [
    'ngSanitize',
    'ui.router',
    'exceedLabs'
  ]);

})();

angular.module(moduleName)
    .constant('hyattEditConfiguration', {
        default: {
            security: {
                jobLevel: '0,1,2,3,4,5,6,7,8,9,10,11,14,16,17,18,19,20,21,23,24,CHICO,MONHC,ZURDO,HKGGA,HKCSA,HKGRO,HKGDM,HKGSL,HKGWS,GURWS,LONHI,MOWWO,RIYSO,BEIWS,SELGS,SHAWO,SHEWS,TYOWO,SINWO,DXBDO,DELDO,ZRHWO',
                visibleToFranchise: 'true',
                businessUnit: 'Brand Experience'
            },
            paths: {
                imageLoaing: '/files/beg/images/icons/loading_main.svg',
                logicalPathBase: '/BEG/'
            },
            moduleTypeValues: [
                { name: '2-COL-A', caption: 'Type + Thumbnail Gallery' },
                { name: '2-COL-B', caption: 'Type + 2 Column Image Gallery with Variable Height' },
                { name: '2-COL-C', caption: 'Type + 2 Column Image' },
                { name: '2-COL-F', caption: 'Type + 2 Column Image with Full Span' },
                { name: '2-COL-G', caption: 'Type + 2 Column Image Gallery' },
                { name: '2-COL-H', caption: 'Type + Image Full Span' },
                { name: '2-COL-I', caption: 'Type + Vertical Image' },
                { name: '2-COL-J', caption: 'Type+ Horizontal Image' },
                { name: 'FULL-K', caption: 'Type + 3 Column Image with Full Span' },
                { name: 'TEXT', caption: 'Type' },
                { name: 'FULL-L', caption: 'Full Width Type + Gallery' },
                { name: 'FULL-M', caption: 'Full Width Type + 3 Column Gallery' },
                { name: 'TYPE-3-IMAGES', caption: 'Type + 3 Images' },
                { name: 'TYPE-4-VARIABLE-IMAGES', caption: 'Type + 4 Variable Images' }
                /* { name: 'Chart Style' },
                { name: 'INDEX' },
               { name: 'PARAGRAPH-WI' },
               { name: 'PARAGRAPH-2I' },
               { name: 'PARAGRAPH-3I' },
               { name: '2-COL-LMI' },
               { name: 'IMG-GAL-A' },
               { name: 'IMG-GAL-B' },
               { name: 'IMG-GAL-C' },
               { name: '3COL-TEXT' },
               { name: 'PARAGRAPH' } */
            ]
        }

    });

angular.module(moduleName)
    .factory('CommentsService', function ($http, $rootScope) {

        var api = {
            createComment: function(params){                
                return $http({ url: '/hyatt-services/userNotifications/createCommentNotification', method: 'POST', params: params });
            },
            getComments: function(params) {
                return $http({ url: '/hyatt-services/userNotifications/getComment', method: 'GET', params: params });
            },
            getUser: function(user, params) {
                return $http({ url: '/hyatt-services/user/'+user, method: 'GET', params: params });
            },
            deleteComment: function(params) {
                return $http({ url: '/hyatt-services/userNotifications/deleteCommentNotification', method: 'POST', params: params });
            }
        };

        return api;
    });
angular.module(moduleName)
.factory('ContentsEditModuleService', function() {
	var api = {
        getModuleRelationBase: function (ctdName, relationId, attributeValue) {
            var relationObjBase = {};
            if (ctdName === 'BEG_ARTICLE') {
                relationObjBase.relationIdXmlName = 'BEG-ARTICLE-CONTENT-ID';
                relationObjBase.relationXmlName = 'article-content';
            } else if (ctdName === 'BEG_SECTION') {
                relationObjBase.relationIdXmlName = 'BEG-SECTION-CONTENT-ID';
                relationObjBase.relationXmlName = 'section-content';
            } else {
                relationObjBase.relationIdXmlName = 'BEG-CHAPTER-CONTENT-ID';
                relationObjBase.relationXmlName = 'chapter-content';
            }
            relationObjBase.relationId = relationId;
            if (attributeValue) {
                relationObjBase.attributeValue = attributeValue;
            }
            return relationObjBase;
        },

        getModuleRelationContentDisplayOrder: function (ctdName, relationId, attributeValue) {
            var relationObj = this.getModuleRelationBase(ctdName, relationId, attributeValue);
            if (ctdName === 'BEG_ARTICLE') {
                relationObj.attributeXmlName = 'BEG-ARTICLE-CONTENT-DISPLAY-ORDER';
            } else if (ctdName === 'BEG_SECTION') {
                relationObj.attributeXmlName = 'BEG-SECTION-CONTENT-DISPLAY-ORDER';
            } else {
                relationObj.attributeXmlName = 'BEG-CHAPTER-CONTENT-DISPLAY-ORDER';
            }
            relationObj.type = "INTEGER";
            return relationObj;
        },


        getModuleRelationModuleType: function (ctdName, relationId, attributeValue) {
            var relationObjModuleType = this.getModuleRelationBase(ctdName, relationId, attributeValue);
            if (ctdName === 'BEG_ARTICLE') {
                relationObjModuleType.attributeXmlName = 'BEG-ARTICLE-CONTENT-TYPE';
            } else if (ctdName === 'BEG_SECTION') {
                relationObjModuleType.attributeXmlName = 'BEG-SECTION-CONTENT-TYPE';
            } else {
                relationObjModuleType.attributeXmlName = 'BEG-CHAPTER-CONTENT-TYPE';
            }
            return relationObjModuleType;
        },

        getModuleRelationTitlePlaceholder: function (ctdName, relationId, attributeValue) {
            var relationObjTitle = this.getModuleRelationBase(ctdName, relationId, attributeValue);
            if (ctdName === 'BEG_ARTICLE') {
                relationObjTitle.attributeXmlName = 'BEG-ARTICLE-CONTENT-TITLE';
            } else if (ctdName === 'BEG_SECTION') {
                relationObjTitle.attributeXmlName = 'BEG-SECTION-CONTENT-TITLE';
            } else {
                relationObjTitle.attributeXmlName = 'BEG-CHAPTER-CONTENT-TITLE';
            }
            relationObjTitle.attributeValue = undefined;
            return relationObjTitle;
        },

        getModuleRelationDescriptionPlaceholder: function (ctdName, relationId, attributeValue) {
            var relationObjTitle = this.getModuleRelationBase(ctdName, relationId, attributeValue);
            if (ctdName === 'BEG_ARTICLE') {
                relationObjTitle.attributeXmlName = 'BEG-ARTICLE-CONTENT-BODY';
            } else if (ctdName === 'BEG_SECTION') {
                relationObjTitle.attributeXmlName = 'BEG-SECTION-CONTENT-BODY';
            } else {
                relationObjTitle.attributeXmlName = 'BEG-CHAPTER-CONTENT-BODY';
            }
            relationObjTitle.attributeValue = undefined;
            return relationObjTitle;
        },

        getModuleRelationModuleCollapsed: function (ctdName, relationId, attributeValue) {
            var relationObjModuleType = this.getModuleRelationBase(ctdName, relationId, attributeValue);
            if (ctdName === 'BEG_ARTICLE') {
                relationObjModuleType.attributeXmlName = 'BEG-ARTICLE-CONTENT-COLLAPSIBLE';
            } else if (ctdName === 'BEG_SECTION') {
                relationObjModuleType.attributeXmlName = 'BEG-SECTION-CONTENT-COLLAPSIBLE';
            } else {
                relationObjModuleType.attributeXmlName = 'BEG-CHAPTER-CONTENT-COLLAPSIBLE';
            }
            return relationObjModuleType;
        },

        getModuleRelationModuleKeywords: function (ctdName, relationId, attributeValue) {
            var relationObjModuleType = this.getModuleRelationBase(ctdName, relationId, attributeValue);
            relationObjModuleType.attributeXmlName = "RELATED-TERMS";
            return relationObjModuleType;
        }
    };
    return api;
});
angular.module(moduleName)
	.factory('ContentsService', function ($http, $httpParamSerializerJQLike) {
		
		function serialize(json) {
            var result = [];
            for (var property in json) {
                if (property !== undefined && json[property] !== undefined) {
                    if (json[property] instanceof Array) {
                        result.push(encodeURIComponent(property) + "=" + json[property].join(','));
                    } else {
                        result.push(encodeURIComponent(property) + "=" + encodeURIComponent(json[property]));
                    }
                }
            }
            return result.join("&");
        }

		function insertMetadata(data) {
			var dateAttr = {
				"attributeXmlName": "LASTMODIFIED",
				"attributeValue": new Date().getTime(),
				"type": "DATE"
			};

			var modifier = {
				"attributeXmlName": "MODIFIER",
				"attributeValue": angular.element('#currentUserId').val()
			};

			if (!data.objects) {
				data.objects = [];
			}

			data.objects.push(modifier);
			data.objects.push(dateAttr);
			return data;
		}

		var api = {
			getContentById: function (contentId, refresh) {
				var params = {};
				params.vgnextoid = contentId;
				if (refresh !== null) {
					params.vgnextrefresh = refresh;
				}
				return $http({ url: '/vgn-ext-templating/v/index.jsp', method: 'GET', params: params });
			},
			updateContent: function (data) {
				data = insertMetadata(data);
				return $http.put('/hyatt-cms/rest/wizard/content/persist', data);
			},

			deleteContent: function (data) {
				data = insertMetadata(data);
				return $http({
					url: '/hyatt-cms/rest/wizard/content/delete',
					method: 'DELETE',
					data: data,
					headers: {
						"Content-Type": "application/json;charset=utf-8"
					}
				});
			},
			deleteContentList: function (data){
				return $http({
					url: '/hyatt-cms/rest/wizard/content/list/delete',
					method: 'DELETE',
					data: data,
					headers: {
						"Content-Type": "application/json;charset=utf-8"
					}
				});
			},
			refreshChannel: function (channelId, refresh) {
				var params = {};
				params.vgnextoid = channelId;
			 
				if (refresh !== null) {
					params.vgnextrefresh = refresh;
				}
				return $http({ url: '/vgn-ext-templating/v/index.jsp', method: 'GET', params: params });
			},
			approveUnapproveContent: function (contentParams) {
			 	return $http({
                    method: 'PUT',
                    url: '/hyatt-cms/rest/wizard/approveUnapprovedContents',
                    data: serialize(contentParams),
                    headers: { 'enctype': 'multipart/form-data' }
                });
			}

		};
		return api;
	});
angular.module(moduleName)
    .factory('ImagesService', function ($http, ContentsService, ContentsEditModuleService) {

        function serialize(json) {
            var result = [];
            for (var property in json) {
                if (property !== undefined && json[property] !== undefined) {
                    if (property instanceof Array) {
                        result.push(encodeURIComponent(property) + "=" + json[property].join(','));
                    } else {
                        result.push(encodeURIComponent(property) + "=" + encodeURIComponent(json[property]));
                    }
                }
            }
            return result.join("&");
        }


        var api = {
            uploadImage: function (imageData) {
                return $http({
                    method: 'POST',
                    url: '/hyatt-cms/rest/wizard/createStaticFile/',
                    data: serialize(imageData),
                    headers: { 'enctype': 'multipart/form-data' }
                });
            },

            deleteImageRelation: function (imageData) {
                return $http({
                    method: 'DELETE',
                    url: '/hyatt-cms/rest/wizard/content/delete/subrelation',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    data: imageData
                });
            },

            deleteStaticFile: function(fileObject) {
                return $http({
                    method: 'DELETE',
                    url: '/hyatt-cms/rest/wizard/removeStaticFile/',
                    data: serialize(fileObject)
                });
            },

            dissociateImageToModule: function (contentObj) {
                return this.deleteImageRelation(contentObj);
            },

            getImageRelation: function (contentId, moduleId, imageRelationId, ctdName, imageId, type) {
                var contentObj = {
                    contentId: contentId
                };
                var moduleRelationObj = ContentsEditModuleService.getModuleRelationBase(ctdName, moduleId, null);
                var imageRelationObj = this.getImageRelationToAssociate(ctdName, imageRelationId, imageId, type);
                moduleRelationObj.objectsRelation = [imageRelationObj];
                contentObj.objectsRelation = [moduleRelationObj];
                return contentObj;
            },

            getImageRelationOrderObject: function (contentId, moduleId, imageRelationId, ctdName, orderValue, type) {
                var contentObj = {
                    contentId: contentId
                };
                var moduleRelationObj = ContentsEditModuleService.getModuleRelationBase(ctdName, moduleId, null);
                var imageRelationOrderObj = this.getImageRelationOrder(ctdName, imageRelationId, orderValue, type);
                moduleRelationObj.objectsRelation = [imageRelationOrderObj];
                contentObj.objectsRelation = [moduleRelationObj];
                return contentObj;
            },

            getFileRelationTitleObject: function (contentId, moduleId, imageRelationId, ctdName, title, type) {
                var contentObj = {
                    contentId: contentId
                };
                var moduleRelationObj = ContentsEditModuleService.getModuleRelationBase(ctdName, moduleId, null);
                var imageRelationOrderObj = this.getFileRelationTitle(ctdName, imageRelationId, title, type);
                moduleRelationObj.objectsRelation = [imageRelationOrderObj];
                contentObj.objectsRelation = [moduleRelationObj];
                return contentObj;
            },

            postImageChange: function (imageRealtionObj) {
                return ContentsService.updateContent(imageRealtionObj);
            },

            getImageRelationBase: function (ctdName, relationId, attributeValue, type) {
                var relationObjBase = {};
                if (ctdName === 'BEG_ARTICLE' && type == 'image') {
                    relationObjBase.relationIdXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-ID';
                    relationObjBase.relationXmlName = 'article-content-image';
                } else if (ctdName === 'BEG_SECTION' && type == 'image') {
                    relationObjBase.relationIdXmlName = 'BEG-SECTION-CONTENT-IMAGE-ID';
                    relationObjBase.relationXmlName = 'section-content-image';
                } else if(ctdName === 'BEG_CHAPTER' && type == 'image'){
                    relationObjBase.relationIdXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-ID';
                    relationObjBase.relationXmlName = 'chapter-content-image';
                } else if(ctdName === 'BEG_ARTICLE' && type == 'file'){
                    relationObjBase.relationIdXmlName = 'BEG-ARTICLE-CONTENT-FILE-ID';
                    relationObjBase.relationXmlName = 'PROD-WEM-MGMT-BEG-ARTICLE-CONTENT-FILE';
                } else if(ctdName === 'BEG_SECTION' && type == 'file'){
                    relationObjBase.relationIdXmlName = 'BEG-SECTION-CONTENT-FILE-ID';
                    relationObjBase.relationXmlName = 'PROD-WEM-MGMT-BEG-SECTION-CONTENT-FILE';
                } else if(ctdName === 'BEG_CHAPTER' && type == 'file'){
                    relationObjBase.relationIdXmlName = 'BEG-CHAPTER-CONTENT-FILE-ID';
                    relationObjBase.relationXmlName = 'PROD-WEM-MGMT-BEG-CHAPTER-CONTENT-FILE';
                }
                relationObjBase.relationId = relationId;
                if (attributeValue) {
                    relationObjBase.attributeValue = attributeValue;
                }
                return relationObjBase;
            },

            getImageRelationToAssociate: function (ctdName, relationId, attributeValue, type) {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE' && type == 'image') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-IMAGE-CONTENT';
                } else if (ctdName === 'BEG_SECTION' && type == 'image') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-IMAGE-CONTENT';
                } else if (ctdName === 'BEG_CHAPTER' && type == 'image'){
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-IMAGE-CONTENT';
                } else if(ctdName === 'BEG_ARTICLE' && type == 'file'){
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-FILE-FILE-CONTENT';
                } else if(ctdName === 'BEG_SECTION' && type == 'file'){
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-FILE-FILE-CONTENT';
                } else if(ctdName === 'BEG_CHAPTER' && type == 'file'){
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-FILE-FILE-CONTENT';
                }
                return relationObjBase;
            },

            getImageRelationOrder: function (ctdName, relationId, attributeValue, type) {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE' && type === 'image') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-DISPLAY-ORDER';
                } else if (ctdName === 'BEG_SECTION' && type === 'image') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-DISPLAY-ORDER';
                } else if(ctdName === 'BEG_CHAPTER' && type === 'image') {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-DISPLAY-ORDER';
                } else if(ctdName === 'BEG_ARTICLE' && type === 'file'){
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-FILE-DISPLAY-ORDER';
                } else if(ctdName === 'BEG_SECTION' && type === 'file'){
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-FILE-DISPLAY-ORDER';
                } else if(ctdName === 'BEG_CHAPTER' && type === 'file'){
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-FILE-DISPLAY-ORDER';
                }
                relationObjBase.type = "INTEGER";
                return relationObjBase;
            },

            getImageRelationCaption: function (ctdName, relationId, attributeValue, type)  {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-CAPTION';
                } else if (ctdName === 'BEG_SECTION') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-CAPTION';
                } else {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-CAPTION';
                }
                return relationObjBase;
            },

            getImageRelationCaptionPosition: function (ctdName, relationId, attributeValue, type)  {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-CAPTION-POSITION';
                } else if (ctdName === 'BEG_SECTION') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-CAPTION-POSITION';
                } else {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-CAPTION-POSITION';
                }
                return relationObjBase;
            },

             getImageRelationTextOverlay: function (ctdName, relationId, attributeValue, type)  {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-TEXT-OVERLAY';
                } else if (ctdName === 'BEG_SECTION') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-TEXT-OVERLAY';
                } else {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-TEXT-OVERLAY';
                }
                return relationObjBase;
            },

            getImageRelationLinkTo: function (ctdName, relationId, attributeValue, type)  {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-LINK-TO';
                } else if (ctdName === 'BEG_SECTION') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-LINK-TO';
                } else {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-LINK-TO';
                }
                return relationObjBase;
            },

             getImageRelationTextOverlayPosition: function (ctdName, relationId, attributeValue, type)  {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-IMAGE-TEXT-OVERLAY-POSITION';
                } else if (ctdName === 'BEG_SECTION') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-IMAGE-TEXT-OVERLAY-POSITION';
                } else {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-IMAGE-TEXT-OVERLAY-POSITION';
                }
                return relationObjBase;
            },

            getFileRelationTitle: function (ctdName, relationId, attributeValue, type)  {
                var relationObjBase = this.getImageRelationBase(ctdName, relationId, attributeValue, type);
                if (ctdName === 'BEG_ARTICLE') {
                    relationObjBase.attributeXmlName = 'BEG-ARTICLE-CONTENT-FILE-TITLE';
                } else if (ctdName === 'BEG_SECTION') {
                    relationObjBase.attributeXmlName = 'BEG-SECTION-CONTENT-FILE-TITLE';
                } else {
                    relationObjBase.attributeXmlName = 'BEG-CHAPTER-CONTENT-FILE-TITLE';
                }
                return relationObjBase;
            }
        };


        return api;
    });

angular.module(moduleName)
    .factory('LikeService', function ($http, $rootScope) {

        var api = {
            like: function(params){                
                return $http({ url: '/hyatt-services/likes/like', method: 'POST', params: params });
            },
            dislike: function(params) {
                return $http({ url: '/hyatt-services/likes/dislike', method: 'POST', params: params });
            },
            totalLikes: function(params) {
                return $http({ url: '/hyatt-services/likes/isLiked', method: 'POST', params: params });
            }
        };

        return api;
    });
angular.module(moduleName)
    .factory('LogService', function ($http, $rootScope) {

        var api = {
            recordUrlServices: "/hyatt-services/begaudit/saveBegAudit",

            prepareRecord: function (ctdType, attributesXml, contentId, actionType) {

                var globalId = angular.element("#currentUserId").val();
                var firstName = angular.element("#firstName").val();
                var lastName = angular.element("#lastName").val();
                var url = window.location.href;

                var json = {
                    "globalId": globalId,
                    "firstName": firstName,
                    "lastName": lastName,
                    "updatedDate": new Date().getTime(),
                    "brandId": $rootScope.currentBrand.brandId,
                    "ctdType": ctdType,
                    "contentId": contentId,
                    "contentUrl": url,
                    "attributes": attributesXml,
                    "actionType": actionType
                };

                return json;
            },

            saveView: function (ctdType, attributesXml, contentId, actionType) {
                try {
                    var jsonRecord = JSON.stringify(this.prepareRecord(ctdType, attributesXml, contentId, actionType));
                    var ajax = jQuery.ajax({
                        url: this.recordUrlServices,
                        type: 'POST',
                        headers: {
                            "Content-Type": "application/json"
                        },
                        contentType: 'application/json',
                        data: jsonRecord,
                        dataType: "html",
                        complete: function (data) {
                        }
                    });
                } catch (err) {
                    //todo
                }
            }
        };

        return api;
    });
angular.module(moduleName)
    .factory('MenusEditService', function ($http, $rootScope) {
        var api = {
            getSectionRelationObject: function () {
                var relationObj = {};
                relationObj.relationIdXmlName = 'BEG-CHAPTER-RELATOR-SECTION-ID';
                relationObj.relationXmlName = 'chapter-section';
                relationObj.attributeXmlName = 'BEG-CHAPTER-RELATOR-SECTION-DISPLAY-ORDER';
                relationObj.type = 'INTEGER';
                return relationObj;
            },

            getArticleRelationObject: function () {
                var relationObj = {};
                relationObj.relationIdXmlName = 'BEG-SECTION-RELATOR-ARTICLE-ID';
                relationObj.relationXmlName = 'section-article';
                relationObj.attributeXmlName = 'BEG-SECTION-RELATOR-ARTICLE-DISPLAY-ORDER';
                relationObj.type = 'INTEGER';
                return relationObj;
            },
            getMenuItems: function (itemSelected) {
                var menuItem = itemSelected;
                if (!menuItem) {
                    menuItem = $('.item-selected');
                    if (menuItem.hasClass('submenu')) {
                        menuItem = menuItem.closest('.menu-item');
                    }
                }
                var menuItems = menuItem.siblings('.menu-item');
                menuItems.push(menuItem[0]);
                return menuItems;
            },

            setOriginalOrderValues: function (itemSelected) {
                var menuItems = this.getMenuItems(itemSelected);
                menuItems.each(function (index) {
                    var currentPosition = $(this).attr('data-order-value');
                    $(this).attr('data-order-original-value', currentPosition);
                });
            },

            verifyOriginalMenuItemPositions: function (itemSelected) {
                var menuItems = this.getMenuItems(itemSelected);
                var menuItemMoved = false;
                menuItems.each(function (index) {
                    var currentPosition = $(this).attr('data-order-value');
                    var originalPosition = $(this).attr('data-order-original-value');
                    if (currentPosition !== originalPosition) {
                        menuItemMoved = true;
                    }
                });
                return menuItemMoved;
            },
            moveMenuItemUp: function (itemSelected) {
                var previous = itemSelected.prev('.menu-item');
                if (previous.length > 0) {
                    itemSelected.insertBefore(previous);
                    var selectedItemOrderValue = itemSelected.attr('data-order-value');
                    var previousOrderValue = previous.attr('data-order-value');
                    itemSelected.attr('data-order-value', previousOrderValue);
                    previous.attr('data-order-value', selectedItemOrderValue);
                }
            },

            getMenuObjectById: function (menuItemId) {
                var menuObject;
                var chapters = angular.copy($rootScope.menu.channel.chapters);
                angular.forEach(chapters, function (chapter) {
                    if (!menuObject) {
                        if (menuItemId.indexOf(chapter.id) !== -1) {
                            menuObject = chapter;
                        } else {
                            angular.forEach(chapter.sections, function (section) {
                                if (!menuObject) {
                                    if (menuItemId.indexOf(section.id) !== -1) {
                                        menuObject = section;
                                    } else {
                                        angular.forEach(section.articles, function (article) {
                                            if (!menuObject) {
                                                if (menuItemId.indexOf(article.id) !== -1) {
                                                    menuObject = article;
                                                }
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    }
                });
                return menuObject;
            },
            getChapterByMenuItemId: function (menuItemId) {
                var chapterResult;
                var chapters = angular.copy($rootScope.menu.channel.chapters);
                angular.forEach(chapters, function (chapter) {
                    if (menuItemId.indexOf(chapter.id) !== -1) {
                        chapterResult = chapter;
                    } else {
                        angular.forEach(chapter.sections, function (section) {
                            if (menuItemId.indexOf(section.id) !== -1) {
                                chapterResult = chapter;
                                chapterResult.sections = [section];
                                chapterResult.sections[0].articles = [];
                            } else {
                                angular.forEach(section.articles, function (article) {
                                    if (menuItemId.indexOf(article.id) !== -1) {
                                        chapterResult = chapter;
                                        chapterResult.sections = [section];
                                        chapterResult.sections[0].articles = [article];
                                    }
                                });
                            }
                        });
                    }
                });
                return chapterResult;
            },

            moveMenuItemDown: function (itemSelected) {
                var next = itemSelected.next('.menu-item');
                if (next.length > 0) {
                    itemSelected.insertAfter(next);
                    var selectedItemOrderValue = itemSelected.attr('data-order-value');
                    var nextOrderValue = next.attr('data-order-value');
                    itemSelected.attr('data-order-value', nextOrderValue);
                    next.attr('data-order-value', selectedItemOrderValue);
                }
            },
            getChannelById: function (channelId, refresh) {
                var params = {};
                params.vgnextoid = channelId;
                if (refresh !== null && refresh !== undefined && refresh !== "") {
                    params.vgnextrefresh = refresh;
                }
                return $http({ url: '/vgn-ext-templating/v/index.jsp', method: 'GET', params: params });
            }
        };
        return api;
    });
angular.module(moduleName)
.factory('ResourceServices', function($http) {
	var api = {
        getModuleRelationBase: function (ctdName, relationId, attributeValue) {
            var relationObjBase = {};
            if (ctdName === 'BEG_ARTICLE') {
                relationObjBase.relationIdXmlName = 'BEG-ARTICLE-CONTENT-ID';
                relationObjBase.relationXmlName = 'article-content';
            } else if (ctdName === 'BEG_SECTION') {
                relationObjBase.relationIdXmlName = 'BEG-SECTION-CONTENT-ID';
                relationObjBase.relationXmlName = 'section-content';
            } else {
                relationObjBase.relationIdXmlName = 'BEG-CHAPTER-CONTENT-ID';
                relationObjBase.relationXmlName = 'chapter-content';
            }
            relationObjBase.relationId = relationId;
            if (attributeValue) {
                relationObjBase.attributeValue = attributeValue;
            }
            return relationObjBase;
        },

        getResourceRelationContentDisplayOrder: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = 'BEG-CONTENT-FILE-RESOURCE-DISPLAY-ORDER';
            relationObj.type = "INTEGER";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationType: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = 'HG-MINI-SITE-RESOURCE-RESOURCE-TYPE';
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationTitle: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = 'HG-MINI-SITE-RESOURCE-TITLE';
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationDescription: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = 'HG-MINI-SITE-RESOURCE-DESCRIPTION';
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationKeywords: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-KEYWORDS";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationDept: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-DEPARTMENTS";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        }, 

        getResourceRelationFile: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-FILE";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getTopIdRelationFile: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-TOP-LEVEL-IDS";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getCreatedDate: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-CREATED";
            relationObj.attributeValue = attributeValue;
            relationObj.type = 'DATE';
            return relationObj;
        },

        getCreatedBy: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-CREATED-BY";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getUpdatedDate: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-UPDATED";
            relationObj.attributeValue = attributeValue;
            relationObj.type = 'DATE';
            return relationObj;
        },

        getUpdatedBy: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-UPDATED-BY";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationYapmo: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-VIDEO-YAPMO-POST";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getResourceRelationEmbed: function (attributeValue) {
            var relationObj = {};
            relationObj.attributeXmlName = "HG-MINI-SITE-RESOURCE-VIDEO-EMBED-CODE";
            relationObj.attributeValue = attributeValue;
            return relationObj;
        },

        getRelationOrder: function(ctdName) {
            var relationObj = {};

            if(ctdName === 'BEG_ARTICLE') {
                relationObj.relationIdXmlName = 'BEG-CONTENT-RESOURCE-RELATOR-RESOURCE-ID';
                relationObj.relationXmlName = 'article-resource-relator';
                relationObj.attributeXmlName = 'BEG-CHAPTER-RESOURCE-RESOURCE-DISPLAY-ORDER';
                relationObj.type = 'INTEGER';
            } else if (ctdName === "BEG_SECTION") {
                relationObj.relationIdXmlName = 'BEG-CONTENT-RESOURCE-RELATOR-RESOURCE-ID';
                relationObj.relationXmlName = 'section-resource-relator';
                relationObj.attributeXmlName = 'BEG-CONTENT-RESOURCE-RELATOR-RESOURCE-DISPLAY-ORDER';
                relationObj.type = 'INTEGER';
            }
            
            return relationObj;
        },

        getMostDownloadedsByChapter: function(params) {
            return $http({ url: '/hyatt-services/service-resources/getResourcesByDownload', method: 'GET', params: params });
        },

        updateDownload: function(params) {
            return $http({ url: '/hyatt-services/service-resources/updateDownload', method: 'POST', params: params });
        },

        deleteDownload: function(params) {
            return $http({ url: '/hyatt-services/service-resources/deleteDownload', method: 'PUT', params: params });
        }
    };
    return api;
});
angular.module(moduleName)
    .directive('hyattAddFiles', ['ContentsService', 'ImagesService', '$state', '$rootScope', '$timeout', 'hyattEditConfiguration', '$compile', 'LogService',
        function (ContentsService, ImagesService, $state, rootScope, $timeout, hyattEditConfiguration, $compile, LogService) {
            return {
                restrict: 'E',
                scope: {},
                link: function (scope, element, attrs) {
                    scope.contentId = attrs.contentId;
                    scope.relatorId = attrs.relatorId;
                    scope.filesLength = attrs.filesLength !== "" ? parseInt(attrs.filesLength)+1 : 1;
                    scope.label = "";
                    rootScope.filesNumber = attrs.filesLength;
                    scope.paragraphFiles = attrs.paragraphFiles !== "" ? JSON.parse(attrs.paragraphFiles) : new Array();
                    scope.ctdName = scope.$parent.data.contents !== undefined ? scope.$parent.data.contents.ctdName : "";
                    scope.buttonInitialName = "New Button";
                    scope.disableSave = true;
                    rootScope.buttonText = "";

                   /*  var isIE11 = !!window.MSInputMethodContext && !!document.documentMode;
                    if(isIE11 && rootScope.y !== null && rootScope.y !== undefined) {
                        setTimeout(function() {window.scrollTo(0,rootScope.y);}, 1000);
                    } */
                    
                    var isChrome = /Chrome/.test(navigator.userAgent) && /Google Inc/.test(navigator.vendor);
                    if(!isChrome && rootScope.y !== null && rootScope.y !== undefined) {
                        //setTimeout(function() {window.scrollTo(0,rootScope.y);}, 2000);
                        setTimeout(function() { $("html, body").animate({ scrollTop: rootScope.y }, "slow"); }, 2000);
                    }
                    
                    scope.toggleNewFile = function ($event) {
                        $($event.currentTarget).parent().next('.new-module-panel').slideToggle(500);
                    };
                    
                    scope.addNewFile = function ($event) {
                        $timeout(function () {
                            angular.element(".order-button").addClass("ng-hide");
                            var target = angular.element($event.currentTarget);
                            var upload = target.next('.browseFile');
                            upload.click();
                        }, 50);
                    };

                    scope.removeAttachedFile = function(){
                        angular.element(".bt-add-attac").removeClass("ng-hide");
                        angular.element(".add-attac").addClass("ng-hide");
                        rootScope.imageObject = {};
                        scope.disableSave = true;
                    };

                    scope.saveFile = function(){
                        rootScope.imageObject.parentContentId = scope.contentId;
                        var files = rootScope.imageObject;
                        var label = scope.label;
                        
                        if(files != null && label != ""){
                            var uploadLoading = angular.element('.modal-add-file-' + scope.relatorId);
                            uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                            //creating satic file at vcm
                            ImagesService.uploadImage(files).then(function (uploadResponse) {
                            angular.element(".add-label").addClass("ng-hide");
                            var newFileId = uploadResponse.data.id;
                            var filePath = uploadResponse.data.logicalPath + uploadResponse.data.name;
                            var ctdName = scope.$parent.data.contents.ctdName;
                            var fileRelationObj = ImagesService.getImageRelation(scope.contentId, scope.relatorId, null, ctdName, newFileId, 'file');
                            fileRelationObj.isApproved = false;
                            //creating file and module association
                            ImagesService.postImageChange(fileRelationObj).then(function (fileChangeResponse) {
                                logActivity(fileRelationObj, "CREATED");
                                var savedRelationId = fileChangeResponse.data.objectsRelation[0].objectsRelation[0].relationId;
                                fileRelationObj = ImagesService.getImageRelationOrderObject(scope.contentId, scope.relatorId, savedRelationId, ctdName, scope.filesLength, 'file');
                                var fileRelationTitle = ImagesService.getFileRelationTitle(ctdName, savedRelationId, label, 'file');
                                fileRelationObj.objectsRelation[0].objectsRelation.push(fileRelationTitle);
                                rootScope.filesNumber++;
                                rootScope.y = window.pageYOffset;
                                fileRelationObj.isApproved = false;
                                //adding title and order
                                setTimeout(function() {saveTitleOrder(fileRelationObj, savedRelationId, label, uploadLoading, ctdName, newFileId, filePath);}, 2000);
                                }, function (error) {
                                    cleanUploadError(uploadLoading);
                                    var fileObject = {
                                        fileId: newFileId
                                    };
                                    ImagesService.deleteStaticFile(fileObject);
                                }); 
                            }, function (error) {
                                cleanUploadError(uploadLoading);
                            });
                        }
                    };

                    scope.removeFile = function(){
                        scope.label = "";
                        angular.element(".bt-add-attac").removeClass("ng-hide");
                        angular.element(".add-attac").addClass("ng-hide");
                        angular.element(".btn-add-button").addClass("ng-disabled");
                        rootScope.fileName = "";
                        scope.buttonInitialName = "New Button";
                        scope.disableSave = true;
                    };

                    scope.inputChange = function(){
                        if (scope.label !== "") {
                            scope.disableSave = false;
                            rootScope.buttonText = scope.label;
                            angular.element(".btn-add-button").removeClass("btn-disabled");
                        } else {
                            scope.disableSave = true;
                            rootScope.buttonText = "";
                            angular.element(".btn-add-button").addClass("btn-disabled");
                        }
                        scope.buttonInitialName = scope.label !== "" ? scope.label : "New Button";
                    };

                    function cleanUpload(uploadLoading){
                        scope.label = "";
                        rootScope.imageObject = {};
                        scope.filesLength++;
                        scope.buttonInitialName = "New Button";
                        uploadLoading.LoadingOverlay("hide", true);
                        angular.element(".modal-add-file-" + scope.relatorId).modal("hide");
                        angular.element(".btn-files-attach").LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        setTimeout(function() {
                            ContentsService.getContentById(scope.contentId, '1').then(function () {
                                $state.reload();
                            });
                        }, 1000);
                    }

                    function cleanUploadError(uploadLoading){
                        scope.label = "";
                        rootScope.imageObject = {};
                        scope.buttonInitialName = "New Button";
                        uploadLoading.LoadingOverlay("hide", true);
                        $('.panel .alert-danger').fadeIn(500, function (e) {
                            $(this).fadeOut(3000);
                        });
                    }

                    function saveTitleOrder(fileRelationObj, savedRelationId, label, uploadLoading, ctdName, newFileId, filePath){
                        ImagesService.postImageChange(fileRelationObj).then(function () {
                            var newButton = {};
                            newButton.id = newFileId;
                            newButton.orderValue = scope.filesLength;
                            newButton.relationId = savedRelationId;
                            newButton.title = label;
                            newButton.isEdit = true;
                            newButton.filePath = filePath; 
                            scope.paragraphFiles.push(newButton);
                            cleanUpload(uploadLoading);
                        }, function (error) {
                            cleanUploadError(uploadLoading);
                            removeAssociation(savedRelationId, ctdName);
                        });
                    }

                    function removeAssociation(savedRelationId, ctdName){
                        var fileRelationObj = ImagesService.getImageRelation(scope.contentId, scope.relatorId, savedRelationId, ctdName, null, 'file');
                        fileRelationObj.isApproved = false;
                        ImagesService.dissociateImageToModule(fileRelationObj)
                        .then(function (response) {
                            angular.element(".download-button-" + scope.buttonId).remove();
                            uploadLoading.LoadingOverlay("hide", true);
                            scope.hideModalRemoveImage();
                            if(scope.isEdit){
                                $state.go($state.current, { refresh: '1' }, { reload: true });
                            }
                        }, function (error) {
                           cleanUploadError(uploadLoading);
                        });
                    }

                    function logActivity(fileRelationObj, actionType){
                        var attributeXmlName = "";

                        if(fileRelationObj.objectsRelation[0] != undefined) {
                            attributeXmlName = fileRelationObj.objectsRelation[0].objectsRelation[0].attributeXmlName;
                        }
                        
                        LogService.saveView(scope.ctdName, attributeXmlName, scope.contentId, actionType);
                    }
                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/add-new-file.html'
            };
}]);

angular.module(moduleName)
    .directive('hyattAddMenuItem', ['ContentsService', 'ContentsEditModuleService', '$state', '$rootScope',
        '$timeout', 'hyattEditConfiguration', 'UtilInlineService', 'MenusEditService', '$location', 'LogService',
        function (ContentsService, ContentsEditModuleService, $state, $rootScope, $timeout,
            hyattEditConfiguration, UtilInlineService, MenusEditService, $location, LogService) {
            return {
                restrict: 'E',
                scope: {
                    'parentId': '=parentId',
                    'itemType': '=itemType',
                    'parentName': '=parentName'
                },

                link: function (scope, element, attrs) {

                    scope.saveNewNavigationItem = function () {

                        var newNavigationItem;
                        newNavigationItem = {};
                        newNavigationItem.objects = [];

                        var xmlNameValue;
                        var chapterParent;
                        var parentMenuItem;
                        var menuItemObject;
                        var parentId = scope.parentId;

                        if (parentId) {
                            menuItemObject = MenusEditService.getMenuObjectById(parentId);
                            if (menuItemObject) {
                                newNavigationItem.logicalPath = UtilInlineService.decode(menuItemObject.logicalPath);
                                parentMenuItem = angular.element('#menu-item-' + parentId);
                                chapterParent = MenusEditService.getChapterByMenuItemId(parentId);
                            }
                        }

                        var objectsGroupRelation = [];
                        var relationObj = {};
                        var ctdXmlNameValue;
                        var attributeXmlNameJobLevel;
                        var jobLevel = hyattEditConfiguration.default.security.jobLevel;
                        var paths = $location.path().split('/');
                        var brandName = paths[2];
                        
                        if(brandName == "Corporate") {
                            jobLevel = hyattEditConfiguration.default.security.jobLevel + ",All";
                        } 

                        if (scope.currentItem.name && scope.currentItem.name.length > 0) {
                            var siblingId;
                            var siblingObj;
                            if (scope.itemType === 'chapter-item') {
                                parentId = undefined;
                                xmlNameValue = 'BEG-CHAPTER-TITLE';
                                ctdXmlNameValue = 'BEG_CHAPTER';
                                attributeXmlNameJobLevel = 'BEG-CHAPTER-JOBLEVEL';
                                chapterParent = {
                                    visibleToFranchise: hyattEditConfiguration.default.security.visibleToFranchise,
                                    jobLevel: jobLevel,
                                    businessUnit: hyattEditConfiguration.default.security.businessUnit,
                                    brands: $rootScope.currentBrand.brandId.toUpperCase()
                                };

                                var path = moduleName !== "brandexpirence" ? configuration_json.folder_configuration_id : hyattEditConfiguration.default.paths.logicalPathBase + $rootScope.currentBrand.name;
                                newNavigationItem.logicalPath = path + '/' + scope.currentItem.name;
                                
                                var chapterOrderValue = angular.element('.chapter-item.menu-item').length + 1;
                                var objectChapterOrder = {
                                    attributeXmlName: 'BEG-CHAPTER-DISPLAY-ORDER',
                                    attributeValue: chapterOrderValue,
                                    type: 'INTEGER'
                                };

                                var groupsDefault = ['CHICO-SGG-CHICO-BEG-CH3-ALL','CHICO-SGG-CHICO-BEG-CH2-ALL'];
                                angular.forEach(groupsDefault, function(group) {
                                    var relationObjGroup = {
                                        relationIdXmlName : 'BEG-AD-GROUPALLOWED-BEG-CH-ID',
                                        relationXmlName : 'PROD-WEM-MGMT-BEG-AD-GROUPALLOWED-BEG-CH',
                                        attributeXmlName: 'BEG-AD-GROUPALLOWED-BEG-CH-CHAPTERID',
                                        attributeValue: group
                                    };
                                    objectsGroupRelation.push(relationObjGroup);
                                });

                                newNavigationItem.objects.push(objectChapterOrder);

                            } else if (scope.itemType === 'article-item') {
                                xmlNameValue = 'BEG-ARTICLE-TITLE';
                                ctdXmlNameValue = 'BEG_ARTICLE';
                                siblingId = parentMenuItem.find('.article-item:last').attr('data-menu-item');
                                if (siblingId) {
                                    siblingObj = MenusEditService.getMenuObjectById(siblingId);
                                    newNavigationItem.logicalPath = UtilInlineService.decode(siblingObj.logicalPath);
                                } else {
                                    newNavigationItem.logicalPath += '/' + UtilInlineService.decode(menuItemObject.name) + ' Articles';
                                }
                                attributeXmlNameJobLevel = 'BEG-ARTICLE-JOBLEVEL';
                                relationObj = MenusEditService.getArticleRelationObject();
                                relationObj.attributeValue = parentMenuItem.find('.article-item.menu-item').length + 1;

                                var groupsArticle = [];
                                groupsArticle = chapterParent.chapterGroupItem.split(',');
                                angular.forEach(groupsArticle, function(group) {
                                    var relationObjGroup = {
                                        relationIdXmlName : 'BEG-AD-GROUPALLOWED-BEG-ART-ID',
                                        relationXmlName : 'PROD-WEM-MGMT-BEG-AD-GROUPALLOWED-BEG-ART',
                                        attributeXmlName: 'BEG-AD-GROUPALLOWED-BEG-ART-ARTICLEID',
                                        attributeValue: group
                                    };
                                    objectsGroupRelation.push(relationObjGroup);
                                });

                                /* angular.forEach(chapterParent.groups, function (group) {
                                    var relationObjGroup = {};
                                    relationObjGroup.relationIdXmlName = 'BEG-AD-GROUPALLOWED-BEG-ART-ARTICLEID';
                                    relationObjGroup.relationXmlName = 'PROD-WEM-MGMT-BEG-AD-GROUPALLOWED-BEG-ART';
                                    relationObjGroup.relationId = group.name;
                                    objectsGroupRelation.push(relationObjGroup);
                                }); */

                            } else if (scope.itemType === 'section-item') {
                                xmlNameValue = 'BEG-SECTION-TITLE';
                                ctdXmlNameValue = 'BEG_SECTION';
                                siblingId = parentMenuItem.find('.section-item:last').attr('data-menu-item');
                                if (siblingId) {
                                    siblingObj = MenusEditService.getMenuObjectById(siblingId);
                                    newNavigationItem.logicalPath = UtilInlineService.decode(siblingObj.logicalPath);
                                } else {
                                    newNavigationItem.logicalPath += '/Sections';
                                }
                                attributeXmlNameJobLevel = 'BEG-SECTION-JOBLEVEL';
                                relationObj = MenusEditService.getSectionRelationObject();
                                relationObj.attributeValue = parentMenuItem.find('.section-item.menu-item').length + 1;
                                
                                var groupsSection = [];
                                groupsSection = chapterParent.chapterGroupItem.split(',');
                                angular.forEach(groupsSection, function(group) {
                                    var relationObjGroup = {
                                        relationIdXmlName: 'BEG-AD-GROUPALLOWED-SEC-ID',
                                        relationXmlName : 'PROD-WEM-MGMT-BEG-AD-GROUPALLOWED-SEC',
                                        attributeXmlName: 'BEG-AD-GROUPALLOWED-SEC-SECTIONID',
                                        attributeValue: group
                                    };
                                    objectsGroupRelation.push(relationObjGroup);
                                });
                            }

                            var newNavigationItemInputValue = scope.currentItem.name;
                            var objectTextValue = {
                                attributeXmlName: xmlNameValue,
                                attributeValue: newNavigationItemInputValue
                            };

                            var brands = chapterParent.brands;
                            if (brands && brands !== '') {
                                var brandsObj = {
                                    attributeXmlName: "BRANDS",
                                    attributeValue: brands
                                };
                                newNavigationItem.objects.push(brandsObj);
                            }
                            var businessUnit = chapterParent.businessUnit;
                            if (!businessUnit || businessUnit === '') {
                                businessUnit = hyattEditConfiguration.default.security.businessUnit;
                            }
                            var businessUnitObj = {
                                attributeXmlName: "COMPANY",
                                attributeValue: businessUnit
                            };
                            newNavigationItem.objects.push(businessUnitObj);

                            var department = chapterParent.department;
                            if (department && department !== '') {
                                var departmentObj = {
                                    attributeXmlName: "DEPARTMENT",
                                    attributeValue: department
                                };
                                newNavigationItem.objects.push(departmentObj);
                            }

                            var regions = chapterParent.regions;
                            if (regions && regions !== '') {
                                var regionObj = {
                                    attributeXmlName: "REGIONS",
                                    attributeValue: regions
                                };
                                newNavigationItem.objects.push(regionObj);
                            }
                            
                            var jobLevel = chapterParent.jobLevel;
                            if (jobLevel && jobLevel !== '') {
                                var jobLevelObj = {
                                    attributeXmlName: attributeXmlNameJobLevel,
                                    attributeValue: jobLevel
                                };
                                newNavigationItem.objects.push(jobLevelObj);
                            }

                            var visibleToFranchise = chapterParent.visibleToFranchise;
                            if (visibleToFranchise && visibleToFranchise !== '') {
                                var visibleToFranchiseObj = {
                                    attributeXmlName: "VISIBLE-TO-FRANCHISE",
                                    attributeValue: visibleToFranchise
                                };
                                newNavigationItem.objects.push(visibleToFranchiseObj);
                            }

                            newNavigationItem.ctdXmlName = ctdXmlNameValue;
                            newNavigationItem.references = {
                                channelId: $rootScope.currentBrand.id
                            };

                            newNavigationItem.objects.push(objectTextValue);
                            var sideBarElement = angular.element('#sidebar');
                            sideBarElement.LoadingOverlay("show", { image: '/files/beg/images/icons/loading_main.svg' });
                            ContentsService.updateContent(newNavigationItem).then(function (response) {
                                logActivity(response, "CREATED");
                                var savedContentId = response.data.contentId;
                                var toAssociateItem = {};
                                if (savedContentId && parentId) {
                                    toAssociateItem = {
                                        contentId: parentId,
                                    };
                                    relationObj.relationId = savedContentId;
                                    toAssociateItem.objectsRelation = [];
                                    toAssociateItem.objectsRelation.push(relationObj);
                                    ContentsService.updateContent(toAssociateItem).then(function (response) {
                                        $rootScope.parentOfLastMenuItemSaved = parentId;
                                        $rootScope.reloadMenu(savedContentId);
                                    }, function (error) {
                                        sideBarElement.LoadingOverlay("hide", true);
                                    });

                                    if (objectsGroupRelation.length) {
                                        toAssociateItem = {
                                            contentId: savedContentId,
                                        };
                                        toAssociateItem.objectsRelation = objectsGroupRelation;
                                        ContentsService.updateContent(toAssociateItem).then(function (response) {
                                        }, function (error) {
                                            sideBarElement.LoadingOverlay("hide", true);
                                        });
                                    }
                                } else {
                                    if (objectsGroupRelation.length) {
                                        toAssociateItem = {
                                            contentId: savedContentId,
                                        };
                                        toAssociateItem.objectsRelation = objectsGroupRelation;
                                        ContentsService.updateContent(toAssociateItem).then(function (response) {
                                            scope.currentItem = {};
                                            $rootScope.reloadMenu(savedContentId);
                                        }, function (error) {
                                            sideBarElement.LoadingOverlay("hide", true);
                                        });
                                    } else {
                                        scope.currentItem = {};
                                        $rootScope.reloadMenu(savedContentId);
                                    }
                                }
                            }, function (error) {
                                sideBarElement.LoadingOverlay("hide", true);
                            });
                        }
                    };

                    scope.removeAddNavigationField = function () {
                        angular.element('.current-add-item').remove();
                        scope.currentChapterItem = { name: '' };
                    };

                    function applyInputFocus() {
                        var inputAddChild = angular.element(element).find('input.child-menu');
                        inputAddChild.focus();
                        var tmpStr = inputAddChild.val();
                        inputAddChild.val('');
                        inputAddChild.val(tmpStr);
                    }

                    function init() {
                        scope.currentItem = {};
                        angular.element(element).find('.add-childMenu').show();
                        if (scope.itemType !== 'chapter-item') {
                            applyInputFocus();
                        }

                    }

                    function logActivity(response, actionType){
                        var attributeXmlName = "";
                        for (var i = 0; i < response.data.objects.length; i++) {
                            attributeXmlName += response.data.objects[i].attributeXmlName + ",";
                        }
                        LogService.saveView(response.data.ctdXmlName, attributeXmlName, response.data.contentId, actionType);
                    }

                    init();

                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/add-menu-item.html'
            };
        }]);
angular.module(moduleName)
    .directive('hyattAddModule', ['ContentsService', 'ContentsEditModuleService', '$state', '$rootScope', '$timeout', 'hyattEditConfiguration', 'LogService',
        function (ContentsService, ContentsEditModuleService, $state, rootScope, $timeout, hyattEditConfiguration, LogService) {
            return {
                restrict: 'E',
                scope: {
                    'contentId': '=contentId',
                    'moduleOrderValue': '=moduleOrderValue',
                    'relationId': '=relationId'
                },
                link: function (scope, element, attrs) {

                    scope.toggleNewModule = function ($event) {
                        $($event.currentTarget).parent().next('.new-module-panel').slideToggle(500);
                    };

                    scope.addNewModule = function (moduleTypeValue, $event) {
                        $('.module-selected').removeClass('module-selected');
                        $($event.currentTarget).addClass('module-selected');
                        scope.moduleType = moduleTypeValue;

                        var contentId = scope.contentId;

                        var newModuleChange = {};
                        newModuleChange.contentId = contentId;
                        newModuleChange.objectsRelation = [];

                        scope.ctdName = rootScope.currentContentType;

                        var moduleItems = angular.element('.module-item');
                        if (moduleItems.length > 0 && moduleItems.length >= scope.moduleOrderValue) {
                            moduleItems.each(function () {
                                var moduleItem = angular.element(this);
                                var moduleRelationId = moduleItem.attr('data-module-item');
                                var currentModuleOrderValue = parseInt(moduleItem.attr("data-order-value"));
                                if (currentModuleOrderValue >= scope.moduleOrderValue) {
                                    currentModuleOrderValue++;
                                }
                                var currentRelationObject = ContentsEditModuleService.getModuleRelationContentDisplayOrder(scope.ctdName, moduleRelationId, currentModuleOrderValue);
                                newModuleChange.objectsRelation.push(currentRelationObject);
                            });
                        }

                        var relationId;
                        var amountOfModules = scope.moduleOrderValue;
                        if (amountOfModules === 0) {
                            amountOfModules++;
                        }
                        var relationNewObj = ContentsEditModuleService.getModuleRelationContentDisplayOrder(scope.ctdName, relationId, amountOfModules);
                        newModuleChange.objectsRelation.push(relationNewObj);
                        newModuleChange.hasNewRelation = true;

                        $($event.currentTarget).closest('.new-module-panel').slideUp(500, function () {
                            postNewModule(newModuleChange);
                        });
                    };

                    function postNewModule(newModuleChange) {
                        var isNewRelation = false;
                        if (newModuleChange.hasNewRelation) {
                            isNewRelation = true;
                            delete newModuleChange.hasNewRelation;
                        }
                        var loadingTarget = angular.element('.panel .modal.loading');
                        loadingTarget.addClass('in').fadeIn();
                        newModuleChange.isApproved = false;
                        ContentsService.updateContent(newModuleChange).then(function (response) {
                            logActivty(newModuleChange, "CREATED");

                            if (isNewRelation) {
                                var relationsResp = response.data.objectsRelation;

                                scope.newRelationId = relationsResp[relationsResp.length - 1].relationId;

                                var relationObj = ContentsEditModuleService.getModuleRelationModuleType(scope.ctdName, scope.newRelationId, scope.moduleType);
                                newModuleChange.objectsRelation = [relationObj];
                                ContentsService.getContentById(newModuleChange.contentId, "1").then(function (resp) {
                                    postNewModule(newModuleChange);
                                });
                            } else {
                                ContentsService.getContentById(newModuleChange.contentId, "1").then(function (resp) {
                                    rootScope.inlineEditorOn = true;
                                    $state.reload();
                                    $timeout(function () {
                                         loadingTarget.removeClass('in').fadeOut();

                                        var moduleId = scope.newRelationId ? scope.newRelationId : scope.relationId;
                                        var moduleElement = angular.element('#module-' + moduleId);

                                        scope.moduleType = undefined;
                                        scope.newRelationId = undefined;
                                        $("html, body").animate({ scrollTop: moduleElement.offset().top }, "slow");
                                        $('.panel .alert-success').fadeIn(500, function () { $(this).fadeOut(3000); });

                                    }, 1000);
                                }, function (error) {
                                     loadingTarget.removeClass('in').fadeOut();
                                    $('.panel .alert-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                                });
                            }
                        }, function (error) {
                             loadingTarget.removeClass('in').fadeOut();
                            $('.panel .alert-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                        });
                    }

                    function init() {
                        scope.moduleTypeValues = hyattEditConfiguration.default.moduleTypeValues;
                        var site = window.location.href.split("/")[6];
                        if(site == 'serviceportal') {
                            for (var i = scope.moduleTypeValues.length - 1; i >= 0; i--) {
                                if(scope.moduleTypeValues[i].name == "TEXT") {
                                    scope.moduleTypeValues = [scope.moduleTypeValues[i]];
                                    break;
                                }
                            }
                        }
                    }

                    function logActivty(moduleObj, actionType){
                        var attributeXmlName = "";
                        for (var i = 0; i < moduleObj.objectsRelation.length; i++) {
                            attributeXmlName += moduleObj.objectsRelation[i].attributeXmlName + ",";
                        }
                        LogService.saveView(scope.ctdName, attributeXmlName, moduleObj.contentId, actionType);
                    }

                    init();
                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/add-new-module.html'

            };
        }]);

angular.module(moduleName)
    .directive('hyattAddResources', ['ContentsService', 'ImagesService', 'ResourceServices','$state', '$rootScope', '$timeout', 'hyattEditConfiguration', '$compile', 'LogService', 'CommentsService', 'LikeService', '$sce', 'UtilInlineService', 'AnalyticService',
        function (ContentsService, ImagesService, ResourceServices, $state, rootScope, $timeout, hyattEditConfiguration, $compile, LogService, CommentsService, LikeService, $sce, UtilInlineService, AnalyticService) {
            return {
                restrict: 'E',
                scope: {
                    'contentId': '=contentId',
                    'resourceFiles': '=resources'
                },
                link: function (scope, element, attrs) {
                    scope.resourceTypes = [{id: "Strategy Guide", label:"Strategy Guide"},{id: "How To", label:"How to"},{id: "Technical Resource", label:"Technical Resource"},{id: "Templates", label:"Template"},{id: "Learning Resource", label:"Learning Resource"},{id: "Research and Insights", label:"Research and Insights"}, {id:"Coming Soon", label:"Coming Soon"}, {id:"Video", label:"Video"}];
                    scope.deptGroup1 = ["Banquets","Engineering","Events"];
                    scope.deptGroup2 = ["Front Office","Guest Services","Housekeeping"];
                    scope.deptGroup3 = ["Human Resources","Outlets","Sales & Marketing"];
                    scope.modalTitle = "Create a new";
                    scope.isEdit = false;
                    scope.resourceLink = window.location.origin + '/portal/site/minisites/shareresource?id=';
                    scope.newComment = '';
                    scope.fileType = "";

                    var chaptersId = UtilInlineService.getChaptersId();
                    
                    // ---- wizard fields ---- \\
                    scope.resourceType = "";
                    scope.title = "";
                    scope.description = "";
                    scope.departments = "";
                    scope.keywords = "";
                    scope.editedId = "";
                    scope.videoLink = "";
                    scope.postLink = "";
                    // ---- end of wizard fields ---- \\
                    scope.comments = [];
                    scope.currentCommentariesResource = null;
                    
                    function init() {
                        var isHome = angular.element("#home").val();

                        $timeout(function() { 
                            if(isHome == "home") {
                                getMostLiked();
                            } else {
                                if(chaptersId.indexOf(scope.contentId) != -1) {
                                    getMostedLikeByChapter(scope.contentId);
                                }
                            }
                        }, 1000);

                        angular.element('#tags input').on('focusout', function(){    
                            var txt= this.value.replace(/[^a-zA-Z0-9\+\-\.\#]/g,''); // allowed characters list
                            if(txt) $(this).before('<span class="tag">'+ txt +'</span>');
                            this.value="";
                            this.focus();
                        }).on('keyup',function(e){
                            // comma|enter (add more keyCodes delimited with | pipe)
                            if(/(188|13)/.test(e.which)) $(this).focusout();
                        });
                          
                        angular.element('#tags').on('click','.tag',function(){
                             angular.element(this).remove(); 
                        });

                        angular.element('.resource-stepper__content__select-file').bind('dragover drop', function(event) {
                            event.stopPropagation(); 
                            event.preventDefault();
                            if (event.type == 'drop') {
                                rootScope.isDropEvent = true;
                                rootScope.dropFiles = event.originalEvent.dataTransfer.files;
                                angular.element(".resource-stepper__content__select-file").find("input").trigger("change");
                            }
                        });
                        
                    }

                    init();

                    // ---- scope functions ---- \\
                    scope.checkNewTagCondition = function(resource) {
                        var shouldShowTag = checkDate(resource.publishDate);
                        if(!shouldShowTag) {
                            shouldShowTag = checkDate(resource.creationDate);
                        }
                        return shouldShowTag;
                    };

                    function checkDate(dateToCheck) {
                        if(dateToCheck) {
                            var resourceDate = new Date(dateToCheck);
                            var date = new Date();
                            date.setDate(date.getDate() - 14);

                            if(resourceDate.getTime() < date.getTime() ) {
                                return false;
                            }
                            return true;
                        }
                        return false;
                    }

                    scope.getTypeClass = function(type) {
                        if(type == "How To") {
                            return "how-to";
                        } else if(type == "Technical Resource") {
                            return "technical-resource";
                        } else if(type == "Templates") {
                            return "templates";
                        } else if(type == "Learning Resource") {
                            return "learning-resource";
                        } else if(type == "Consumer Insights") {
                            return "consumer-insights";
                        } else if(type == "Coming Soon") {
                            return "coming-soon";
                        } else if(type == "Research and Insights") {
                            return "consumer-insights";
                        } else if(type == "Video") {
                            return "video";
                        }
                        return "";
                    };

                    scope.getTypeTitle = function(type) {
                        if(type){
                            for(var i=0;scope.resourceTypes;i++){
                                if(scope.resourceTypes[i].id === type){
                                    return scope.resourceTypes[i].label;
                                }
                            }
                            return type;
                        }
                        else{
                            return '';
                        }
                    };

                    scope.enableNext = function(type, value) {
                        if(type == "text" || type == "keywords") {
                            if(type == "keywords" && angular.element(".tag").length > 0) {
                                enableButton();
                            } else if (value != "") {
                                enableButton();
                            } else {
                                disableButton();
                            }
                        } else if ((type == "check" || type == "file") && !scope.isEdit) {
                            disableButton();
                        } else if(type == "video"){ 
                            if(scope.videoLink != "" && scope.postLink != "") {
                                if(validateEmbed(scope.videoLink)) {
                                    angular.element(".embed-link").removeClass("embed-error");
                                    enableButton();
                                } else {
                                    angular.element(".embed-link").addClass("embed-error");
                                    disableButton();
                                }
                            }
                        } else {
                            scope.getFileType(scope.resourceType);
                            enableButton();
                        }
                    };

                    scope.nextStep = function(attr, type, value) {
                        if(scope.resourceType == "Coming Soon" && attr == "description-document") {
                            cleanFormFieldsComingSoon();
                            attr = 'done';
                        }

                        angular.element(".resource-stepper").removeClass("active");
                        angular.element("."+attr).addClass("active");
                        angular.element(".next-button").prop("disabled", true);
                        scope.enableNext(type, value);
                    };

                    scope.backStep = function(attr) {
                        angular.element(".resource-stepper").removeClass("active");
                        angular.element("."+attr).addClass("active");
                        angular.element(".next-button").prop("disabled", false);
                    };

                    scope.closeWizard = function(){
                        cleanFormFields();
                        angular.element(".resource-stepper__content__files").addClass("ng-hide");
                        angular.element(".resource-stepper__content__select-file").removeClass("ng-hide");
                        disableButton();
                        angular.element(".resource-stepper").removeClass("active");
                        angular.element(".type-document").addClass("active");
                        angular.element(".overlay-resource").removeClass("active");
                        scope.modalTitle = "Create a new";
                        scope.isEdit = false;
                    };

                    scope.selectDept = function(value){
                        if(scope.departments.indexOf(value.dept) != -1) {
                            var dept = scope.departments.replace(value.dept,"");
                            dept = dept.replace(",,","").replace(/^,/, '');
                            scope.departments = dept;
                        } else {
                            if(scope.departments == "") {
                                scope.departments = value.dept;
                            } else {
                                scope.departments += "," + value.dept;
                            }   
                        }

                        if(scope.departments == "") {
                            disableButton();
                        } else {
                            enableButton();
                        }
                    };

                    scope.addNewFile = function ($event) {
                        $timeout(function () {
                            var target = angular.element($event.currentTarget);
                            var upload = target.next('.browseFile');
                            upload.click();
                        }, 50);
                    };

                    scope.removeFile = function(){
                        angular.element(".resource-stepper__content__files").addClass("ng-hide");
                        angular.element(".resource-stepper__content__select-file").removeClass("ng-hide");
                        rootScope.fileName = "";
                        rootScope.imageObject = null;
                        disableButton();
                    };

                    scope.save = function(){
                        if(scope.isEdit) {
                            updateAction();
                        } else {
                            saveAction();
                        }
                    };

                    scope.encodeURIComponent = function(uri){
                        uri = encodeURIComponent(uri);
                        return uri;
                    };

                    scope.showRemoveWarning = function($event) {
                        var target = angular.element($event.currentTarget);
                        if(!target.hasClass("remove-disable")) {
                            target.next('.resource-note__confirm-del').addClass("active");
                            angular.element(".remove-resource").addClass("remove-disable");
                            angular.element('.overlay-resource-card').addClass("active");
                        }
                    };

                    scope.hideRemoveWarning = function() {
                        angular.element(".resource-note__confirm-del").removeClass("active");
                        angular.element(".remove-resource").removeClass("remove-disable");
                        angular.element('.overlay-resource-card').removeClass("active");
                    };

                    scope.onResourceCardClick = function(tag, type, link) {
                        $timeout(function() {
                            if(type == "Video") {
                                var frame = angular.element(unescapeHtml(link));
                                var src = frame.attr("src");
                                src = src.replace(/"/g, "");
                                angular.element("#igniteFrameContainer").css("display","inline-table");
                                openIgniteFrame(src, 720, 480);
                            } else {
                                angular.element(tag)[0].click();
                            }
                        }, 0);
                    };

                    scope.removeResource = function(id, attrId) {
                        var uploadLoading = angular.element('#print-section');
                        uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        scope.hideRemoveWarning();
                        
                        var resourceRemoved = {};
                        resourceRemoved.objectsRelation = [];
                        resourceRemoved.contentId = scope.contentId;
                        resourceRemoved.isApproved = false;
                        var ctdName = scope.$parent.data.contents.ctdName;
                        
                        var relationObj;
                        relationObj = ResourceServices.getRelationOrder(ctdName);
                        relationObj.relationId = id;
                        resourceRemoved.objectsRelation.push(relationObj);
                        
                        ContentsService.deleteContent(resourceRemoved).then(function (response) {
                            ContentsService.getContentById(scope.contentId, '1').then(function () {
                                var params = {resourceId:attrId};
                                ResourceServices.deleteDownload(params);
                                uploadLoading.LoadingOverlay("hide", true);
                                $state.reload();
                            });
                        }, function (error) {
                            uploadLoading.LoadingOverlay("hide", true);
                            showError();
                        });
                    };

                    scope.manageLike = function(id) {
                        var params = {};
                        params.contentId = id;
                        params.currentUserName = angular.element("#firstName").val() + angular.element("#lastName").val(); 
                        params.userId = angular.element("#currentUserId").val();

                        var resource = getResource(id);
                        if(resource.isLiked == "liked.svg") {
                           LikeService.dislike(params);
                           scope.resourceFiles[resource.index].totalLikes--; 
                           scope.resourceFiles[resource.index].isLiked = isResourceLiked(0);
                        } else {
                           LikeService.like(params);
                           scope.resourceFiles[resource.index].totalLikes++;
                           scope.resourceFiles[resource.index].isLiked = isResourceLiked(1);
                        }
                    };

                    scope.editResource = function(id) {
                        var resource = getResource(id);
                        scope.isEdit = true;
                        scope.title = $sce.trustAsHtml(UtilInlineService.decode(resource.title));
                        scope.description = $sce.trustAsHtml(UtilInlineService.decode(resource.description));
                        scope.resourceType = resource.type;
                        angular.element('.overlay-resource input[name=type-resource]').val(resource.editType);
                        scope.departments = UtilInlineService.decode(resource.departments);
                        scope.keywords = resource.keywords;
                        scope.editedId = id;
                        scope.videoLink = $sce.trustAsHtml(UtilInlineService.decode(resource.videoEmbedCode));
                        scope.postLink = resource.yapmoLink;
                        var file = resource.filePath;
                        setFile(file);
                        checkDepartments();
                        addKeywords();
                        scope.modalTitle = "Edit";
                        angular.element(".overlay-resource").addClass("active");
                        enableButton();
                    };

                    scope.initializeLikes = function(){
                        for(var i = 0; i<scope.resourceFiles.length; i++) {
                            var params = {};
                            params.contentId = scope.resourceFiles[i].id;
                            params.currentUserName = angular.element("#firstName").val() + angular.element("#lastName").val(); 
                            params.userId = angular.element("#currentUserId").val();
                            fillLike(params, i);
                            fillDownloads(params, i);
                        }
                    };

                    scope.updateDownload = function(resource, event, isDownload){
                        
                        if(window.navigator.msSaveOrOpenBlob && isDownload && resource.type != "Video") {
                            event.preventDefault();
                            downloadFile(resource.filePath, event);
                        }
                        
                        var topLevel = resource.topLevelIds.split(",");
                        var params = {resourceId: resource.attrId, topLevelId: topLevel[0], contentId: resource.id};
                        ResourceServices.updateDownload(params);
                    };

                    scope.openComments = function(resource){
                        scope.currentCommentariesResource = resource;
                        var params = {
                            contentId: resource.id
                        };
                        CommentsService.getComments(params).then(function(response){
                            scope.comments = response.data.comments;
                            scope.comments.forEach(function(element){
                                element.formattedDate = formatDate(element.createDate);

                                CommentsService.getUser(element.userId, {}).then(function(response){
                                    var user = response.data.user;
                                    element.completeName = user.firstName + ' ' + user.lastName;
                                });
                            });
                        });
                    };

                    scope.closeComment = function(){
                        scope.currentCommentariesResource = null;
                    };

                    scope.postComment = function(){
                        if(scope.newComment.trim() !== '') {
                            var params = {
                                contentId: scope.currentCommentariesResource.id,
                                userId: angular.element("#currentUserId")[0].value,
                                description: scope.newComment
                            };
                            CommentsService.createComment(params).then(function(response){
                                scope.openComments(scope.currentCommentariesResource);
                                scope.newComment = '';                        
                            });
                        }
                    };

                    scope.saveExceed = function(id, type, title){
                        var resource = {
                            id : id + "_" + type,
                            title: title
                        };
                        AnalyticService.saveView(resource,'ContentInstance');
                    };

                    scope.getFileType = function(type) {
                        if(type == "Video") {
                            scope.fileType = "Video";
                        } else {
                            scope.fileType = "Ohers";
                            scope.videoLink = "";
                            scope.postLink = "";
                        }
                    };

                    scope.deleteComment = function($event, comment){
                        var el = angular.element($event.currentTarget);
                        if(el.hasClass("deleteComment")) {
                            el.removeClass("deleteComment");
                            el.addClass("deleteCommentConfirm");
                        } else {
                            var deleteLoading = angular.element('.resource-comment-main');
                            deleteLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                            var params = {
                                contentId: comment.contentId,
                                id: comment.id
                            };
                            CommentsService.deleteComment(params).then(function(response){
                                removeComment(params);
                                deleteLoading.LoadingOverlay("hide",true);                       
                            });
                        }
                    };

                    scope.showDelete = function(id){
                        var userId = angular.element("#currentUserId")[0].value;
                        if(userId == "1228200" || userId == "1370705") {
                            return true;
                        }
                        return userId == id;
                    };
                    // ---- end of scope functions ---- \\

                    
                    // ---- auxiliary functions ---- \\
                    function validateEmbed(embed){
                        var patt = new RegExp("(?:<iframe[^>]*)(?:(?:\/>)|(?:>.*?<\/iframe>))");
                        return patt.test(embed);
                    }

                    function unescapeHtml(text) {
                        return text
                             .replace(/&amp;/g, "&")
                             .replace(/&lt;/g, "<")
                             .replace(/&gt;/g, ">")
                             .replace(/&quot;/g, '"');
                     }

                    function removeComment(params){
                        for (var i = 0; i <= scope.comments.length -1; i++) {
                            var comment = scope.comments[i];
                            if(comment.id == params.id && comment.contentId == params.contentId) {
                                scope.comments.splice(i, 1);
                                break;
                            }
                        }
                    }

                    function returnMontName(dateMonth){
                        var monthNames = [
                            "JAN", "FEB", "MAR",
                            "APR", "MAY", "JUN", "JUL",
                            "AUG", "SEP", "OCT", "NOV", "DEC"
                        ];
                        return monthNames[dateMonth];
                    }

                    function formatDate(dateInMili){
                        var date = new Date(dateInMili);
                        var formattedDate = date.getDate() + ' ' + returnMontName(date.getMonth()) + ' ' + date.getFullYear()+ ' '+ date.getHours()+':'+ date.getMinutes();
                        return formattedDate;
                    }

                    function downloadFile(url) {
                        var fileName = url.split("/");
                        fileName = fileName[fileName.length-1];
                        var blob = null;
                        var xhr = new XMLHttpRequest();
                        xhr.open("GET", url);
                        xhr.responseType = "blob";
                        xhr.onload = function() 
                        {
                           blob = this.response;
                           window.navigator.msSaveOrOpenBlob(blob, fileName);
                        };
                        xhr.send();
                    }

                    function fillLike(params, index) {
                        LikeService.totalLikes(params).then(function (response) {
                            var like = response.data.isLiked[0];
                            scope.resourceFiles[index].totalLikes = like.totalLike;
                            scope.resourceFiles[index].isLiked = isResourceLiked(like.isLiked);
                        });
                    }

                    //TODO: CREATE ROUTE TO GET ONLY COMMENTS NUMBER, INSTEAD OF GETTING ALL COMMENTS
                    function fillDownloads(params, index) {
                        CommentsService.getComments(params).then(function (response) {
                            scope.resourceFiles[index].totalComments = response.data.comments.length;
                        });
                    }

                    function addKeywords(){
                        var keywords = scope.keywords.split(",");
                        for (var i = 0; i < keywords.length; i++) {
                            if(keywords[i] != "") {
                                var tag = "<span class='tag'>" + keywords[i] + "</span>";
                                angular.element("#tags .key-words").append(tag);
                            }
                        }

                        scope.keywords = "";
                    }

                    function setFile(file) {
                        var fileName = file.split("/");
                        rootScope.fileName = fileName[fileName.length - 1];
                        angular.element(".resource-stepper__content__files").removeClass("ng-hide");
                        angular.element(".resource-stepper__content__select-file").addClass("ng-hide");
                    }

                    function updateAction(){
                        angular.element(".resource-loader").addClass("active");
                        if(rootScope.imageObject != null && rootScope.imageObject != "") {
                            rootScope.imageObject.parentContentId = scope.contentId;
                            var files = rootScope.imageObject;
                            ImagesService.uploadImage(files).then(function (uploadResponse) {
                                updateResource(uploadResponse.data.placementPath);
                            }, function (error) {
                                showError();
                            });
                        } else {
                            updateResource(null);
                        }
                    }

                    function saveAction(){
                        angular.element(".resource-loader").addClass("active");
                        if(rootScope.imageObject != null && rootScope.imageObject != "") {
                            rootScope.imageObject.parentContentId = scope.contentId;
                            var files = rootScope.imageObject;
                            ImagesService.uploadImage(files).then(function (uploadResponse) {
                                createResource(uploadResponse.data.placementPath);
                            }, function (error) {
                                showError();
                            });
                        } else {
                            createResource(null);
                        }
                    }

                    function getResource(id) {
                        var resource = {};
                        for (var i = 0; i < scope.resourceFiles.length; i++) {
                            if(scope.resourceFiles[i].id == id) {
                                resource = scope.resourceFiles[i];
                                resource.index = i;
                                return resource;
                            }
                        }
                    }

                    function checkDepartments() {
                        var depts = scope.departments.split(",");
                        for(var i = 0; i < depts.length; i++) {
                            if(depts[i] != "") {
                                angular.element(".overlay-resource input[value='" + depts[i].replace('&amp;','&') + "']").prop('checked', true);
                            }
                        }
                    }

                    function updateResource(placementPath) {
                    	
                    	var currentUserGlobalID = angular.element("#currentUserId")[0].value;
                        var resource = {};
                        resource.contentId = scope.editedId;
                        resource.objects = [];

                        var relationType = ResourceServices.getResourceRelationType(scope.resourceType);
                        resource.objects.push(relationType);
                        
                        var relationTitle = ResourceServices.getResourceRelationTitle($sce.valueOf(scope.title));
                        resource.objects.push(relationTitle);
                        
                        var relationDescription = ResourceServices.getResourceRelationDescription($sce.valueOf(scope.description));
                        resource.objects.push(relationDescription);
                        
                        var relationDepartment = ResourceServices.getResourceRelationDept(scope.departments);
                        resource.objects.push(relationDepartment);

                        if(scope.videoLink != null) {
                            var yapmoLink = ResourceServices.getResourceRelationYapmo(scope.postLink);
                            resource.objects.push(yapmoLink);

                            var embedVideo = ResourceServices.getResourceRelationEmbed(scope.videoLink);
                            resource.objects.push(embedVideo);
                        }
                        
                        //var updatedDate = ResourceServices.getUpdatedDate(new Date().getTime());
                        //resource.objects.push(updatedDate);
                        
                        //var updatedBy = ResourceServices.getUpdatedBy(currentUserGlobalID);
                        //resource.objects.push(updatedBy);
                        
                        if(placementPath != null) {
                            var relationFile = ResourceServices.getResourceRelationFile(placementPath);
                            resource.objects.push(relationFile);
                        }

                        var keyWords = ResourceServices.getResourceRelationKeywords(getKeyWords());
                        resource.objects.push(keyWords);

                        ContentsService.updateContent(resource).then(function (response) {
                            ContentsService.getContentById(scope.contentId, '1').then(function () {
                                angular.element(".resource-loader").removeClass("active");
                                scope.closeWizard();
                                $state.reload();
                            });
                        }, function (error) {
                            showError();
                        });
                    }

                    function createResource(placementPath) {
                    	var currentUserGlobalID = angular.element("#currentUserId")[0].value;
                        var resource = {};

                        //UtilInlineService.decode(menuItemObject.logicalPath);
                        resource.logicalPath = configuration_json.folder_configuration_id +"/Site Resources/";
                        resource.ctdXmlName = "HG_MINI_SITE_RESOURCE";
                        resource.isApproved = false;

                        resource.references = {
                            channelId: configuration_json.channel_configuration_id
                        };

                        resource.objects = [];
                        
                        var relationType = ResourceServices.getResourceRelationType(scope.resourceType);
                        resource.objects.push(relationType);
                        
                        var relationTitle = ResourceServices.getResourceRelationTitle(scope.title);
                        resource.objects.push(relationTitle);
                        
                        var relationDescription = ResourceServices.getResourceRelationDescription(scope.description);
                        resource.objects.push(relationDescription);
                        
                        var relationDepartment = ResourceServices.getResourceRelationDept(scope.departments);
                        resource.objects.push(relationDepartment);
                        
                        if(placementPath != null) {
                            var relationFile = ResourceServices.getResourceRelationFile(placementPath);
                            resource.objects.push(relationFile);
                        }

                        var keyWords = ResourceServices.getResourceRelationKeywords(getKeyWords());
                        resource.objects.push(keyWords);

                        var yapmoLink = ResourceServices.getResourceRelationYapmo(scope.postLink);
                        resource.objects.push(yapmoLink);

                        if(scope.videoLink != null) {
                            var yapmoLink = ResourceServices.getResourceRelationYapmo(scope.postLink);
                            resource.objects.push(yapmoLink);

                            var embedVideo = ResourceServices.getResourceRelationEmbed(scope.videoLink);
                            resource.objects.push(embedVideo);
                        }

                        //var createdDate = ResourceServices.getCreatedDate(new Date().getTime());
                        //resource.objects.push(createdDate);
                        
                        //var createdBy = ResourceServices.getCreatedBy(currentUserGlobalID);
                        //resource.objects.push(createdBy);
                        
                        //var updatedDate = ResourceServices.getUpdatedDate(new Date().getTime());
                        //resource.objects.push(updatedDate);
                        
                        //var updatedBy = ResourceServices.getUpdatedBy(currentUserGlobalID);
                        //resource.objects.push(updatedBy);
                        
                        var topLevel = "";

                        for (var i = 0; i < rootScope.breadcrumb.length; i++) {
                            topLevel += rootScope.breadcrumb[i].id +  ",";
                        }

                        topLevel = topLevel.replace(/,(?=[^,]*$)/, '');

                        var topLevelIds = ResourceServices.getTopIdRelationFile(topLevel);
                        resource.objects.push(topLevelIds);

                        ContentsService.updateContent(resource).then(function (response) {
                            var savedContentId = response.data.contentId;
                            var toAssociateItem = {};
                            var relationObj = {};
                            var ctdName = scope.$parent.data.contents.ctdName;
                            relationObj = ResourceServices.getRelationOrder(ctdName);
                            relationObj.attributeValue = scope.resourceFiles != undefined ? scope.resourceFiles.length + 1 : 1;

                            if (savedContentId && scope.contentId) {
                                toAssociateItem = {
                                    contentId: scope.contentId,
                                };
                                
                                relationObj.relationId = savedContentId;
                                toAssociateItem.objectsRelation = [];
                                toAssociateItem.objectsRelation.push(relationObj);
                                toAssociateItem.isApproved = false;

                                ContentsService.updateContent(toAssociateItem).then(function (response) {
                                    setTimeout(function() {
                                        ContentsService.getContentById(scope.contentId, '1').then(function () {
                                            angular.element(".resource-loader").removeClass("active");
                                            scope.closeWizard();
                                            $state.reload();
                                        });
                                    }, 1000);
                                }, function (error) {
                                    showError();
                                });
                            }
                        }, function (error) {
                            showError();
                        });
                    }

                    function enableButton(){
                        angular.element(".next-button").prop("disabled", false);
                    }

                    function disableButton(){
                        angular.element(".next-button").prop("disabled", true);
                    }

                    function cleanFormFields(){
                        scope.title = "";
                        scope.description = "";
                        scope.resourceType = "";
                        scope.departments = "";
                        rootScope.fileName = "";
                        rootScope.imageObject = "";
                        scope.keywords = "";
                        scope.videoLink = "";
                        scope.postLink = "";
                        angular.element(".tag").remove();
                        angular.element('input:checkbox').prop('checked', false); 
                    }

                    function cleanFormFieldsComingSoon(){
                        scope.description = "";
                        scope.departments = "";
                        rootScope.fileName = "";
                        rootScope.imageObject = "";
                        scope.keywords = "";
                        angular.element(".tag").remove();
                        angular.element('input:checkbox').prop('checked', false); 
                    }

                    function showError(){
                        angular.element(".resource-loader").removeClass("active");
                        angular.element(".resource-error").addClass("active");
                        setTimeout(function() {
                            angular.element(".resource-error").removeClass("active"); 
                            scope.closeWizard();
                        }, 4000);
                    }

                    function getMostLiked(){
                        //function to return most liked at home
                        var params = {topLevelId: '', limit: 6};
                        ResourceServices.getMostDownloadedsByChapter(params).then(function(response){
                            if(response.data.resources.length > 0) {
                                scope.resourceFiles = response.data.resources;
                            }
                        });
                    }

                    function getMostedLikeByChapter(id) {
                        var params = {topLevelId: id, limit: 6};
                        ResourceServices.getMostDownloadedsByChapter(params).then(function(response){
                            if(response.data.resources.length > 0) {
                                scope.resourceFiles = response.data.resources;
                            }
                        });
                    }

                    function getKeyWords(){
                        var tags = angular.element(".tag");

                        if(tags.length == 1) {
                            scope.keywords = tags[0].innerHTML;
                        } else if (tags.length > 1){
                            scope.keywords = "";
                            for(var i = 0; i<tags.length; i++) {
                                scope.keywords += tags[i].innerHTML + ",";
                            }
                            scope.keywords = scope.keywords.replace(/,(?=[^,]*$)/, '');
                        }

                        return scope.keywords;
                    }

                    function isResourceLiked(value) {
                        if(value == 1) {
                            return "liked.svg";
                        }
                        return "like-icon.svg";
                    }
                    // --- end of auxiliary functions  ---- \\

                },
                templateUrl: '/vgn-ext-templating/minisites/jsp/directives-templates/add-resource.html'
            };
}]);

angular.module(moduleName)
    .directive('hyattEditFiles', ['ContentsService', 'ImagesService', '$state', '$rootScope', '$timeout', 'hyattEditConfiguration', 'LogService', 'AnalyticService', '$compile',
        function (ContentsService, ImagesService, $state, rootScope, $timeout, hyattEditConfiguration, LogService, AnalyticService, $compile) {
            return {
                restrict: 'E',
                scope: {},
                link: function (scope, element, attrs) {
                    scope.contentId = attrs.contentId;
                    scope.label = attrs.label.replace(/&amp;/g,"&");
                    scope.buttonId = attrs.buttonId;
                    scope.relatorId = attrs.relatorId;
                    rootScope.fileName = "";
                    scope.filePath = attrs.fileName.replace(/&amp;/g,"&");
                    scope.isEdit = attrs.isEdit === 'true' ? true:false;
                    scope.ctdName = attrs.ctdName !== undefined ? attrs.ctdName : scope.$parent.data.contents.ctdName;
                    rootScope.imageObject = null;
                    scope.labelButton = scope.label;
                    scope.fileId = attrs.fileId;
                    scope.orderValue = attrs.orderValue;
                    scope.newOrderValue = scope.orderValue;
                    scope.activateOrderChange = false;
                    scope.buttonName = scope.label;

                    var fileName = scope.filePath.split("/");
                    scope.completeButtonName = fileName[fileName.length -1];

                    setTimeout(function() {
                        var directive = angular.element('.exceed-call-'+scope.buttonId).append('<call-exceed data-content-id="'+scope.contentId+'" data-buttom-id="'+scope.buttonId+'" data-type-object="StaticFile"></call-exceed>');
                        $compile(directive)(scope);  
                    }, 1000);

                   /*  var isIE11 = !!window.MSInputMethodContext && !!document.documentMode;
                    if(isIE11 && rootScope.y !== null && rootScope.y !== undefined) {
                        setTimeout(function() {window.scrollTo(0,rootScope.y);}, 2000);
                    } */

                    var isChrome = /Chrome/.test(navigator.userAgent) && /Google Inc/.test(navigator.vendor);
                    if(!isChrome && rootScope.y !== null && rootScope.y !== undefined) {
                        //setTimeout(function() {window.scrollTo(0,rootScope.y);}, 2000);
                        setTimeout(function() { $("html, body").animate({ scrollTop: rootScope.y }, "slow"); }, 2000);
                    }

                    if(scope.isEdit){
                        angular.element(".box-bts-file").removeClass("ng-hide");
                    }

                    scope.saveExceed = function(){
                        var fileName = scope.filePath.split("/");
                        var file = {
                            id : scope.contentId,
                            title: fileName[fileName.length -1]
                        };
                        AnalyticService.saveView(file,'StaticFile');
                    };

                    scope.editFile = function(){
                        var uploadLoading = angular.element('.modal-content');
                        uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        var newText = scope.labelButton;
                        var oldTextValue = angular.element(".edit-" + scope.buttonId).val();
                        if(rootScope.imageObject !== null && rootScope.imageObject !== undefined && rootScope.imageObject !== ""){
                            updateTitleFiles(newText, oldTextValue, uploadLoading);
                        }
                        else if(newText !== "" && newText !== oldTextValue) {
                            updateTitle(newText, uploadLoading, false);
                        } else {
                            uploadLoading.LoadingOverlay("hide", true);
                            angular.element(".modal").modal("hide");
                        }
                    };

                    scope.cancelFileEdition = function(){
                        angular.element(".bt-edit-attac").addClass("ng-hide");
                        angular.element(".edit-attac").removeClass("ng-hide");
                        scope.labelButton = scope.label;
                        scope.buttonName = scope.labelButton;
                    };

                    scope.removeFile = function($event){
                        var uploadLoading;
                        if(scope.isEdit){
                            uploadLoading = angular.element('#print-section');
                        } else {
                            uploadLoading = angular.element('.file-upload');
                        }
                        uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        var fileRelationObj = ImagesService.getImageRelation(scope.contentId, scope.relatorId, scope.buttonId, scope.ctdName, null, 'file');
                        fileRelationObj.isApproved = false;
                        ImagesService.dissociateImageToModule(fileRelationObj)
                        .then(function (response) {
                            logActivityRemove(response, "REMOVED");
                            angular.element(".download-button-" + scope.buttonId).remove();
                            scope.hideModalRemoveImage();
                            rootScope.filesNumber--;
                            rootScope.y = window.pageYOffset;
                            reload();
                            //removeStaticFile(null, uploadLoading);
                        }, function (error) {
                           uploadLoading.LoadingOverlay("hide", true);
                        });
                       
                    };

                    scope.updateFile = function ($event) {
                        $timeout(function () {
                                var target = angular.element($event.currentTarget);
                                var upload = target.next('.browseFile');
                                upload.click();
                        }, 50);
                    };

                    scope.attachNewFile = function(){
                        angular.element(".bt-edit-attac").removeClass("ng-hide");
                        angular.element(".edit-attac").addClass("ng-hide");
                    };

                    scope.getFileName = function(){
                        angular.element(".order-button").addClass("ng-hide");
                        if(attrs.fileName.split("/").length > 1){
                            rootScope.fileName = attrs.fileName.split("/")[4];
                        } else {
                            rootScope.fileName = attrs.fileName;
                        }
                        rootScope.$apply();
                    };

                    scope.hideModalRemoveImage = function () {
                        var modalRemoveImage = angular.element(element).find('.remove-file-warning');
                        modalRemoveImage.removeClass('in').fadeOut();
                    };

                    scope.showModalRemoveImage = function () {
                        angular.element(".order-button").addClass("ng-hide");
                        var modalRemoveImage = angular.element(element).find('.remove-file-warning');
                        modalRemoveImage.addClass('in').show();
                    };

                    scope.moveFileUp = function () {
                        var buttons = [];
                        var itemSelected = getElement();
                        var previous = itemSelected.prev('.content-files');

                        var selectedButton = itemSelected.find("hyatt-edit-files");
                        var previousButton = previous.find("hyatt-edit-files");
                        buttons.push(selectedButton, previousButton);

                        if (previous.length > 0) {
                            itemSelected.insertBefore(previous);
                            var selectedItemOrderValue = selectedButton.attr('order-value');
                            var previousOrderValue = previousButton.attr('order-value');
                            selectedButton.attr('order-value', previousOrderValue);
                            previousButton.attr('order-value', selectedItemOrderValue);
                            updateOrder(buttons);
                        }
                    };

                    scope.moveFileDown = function() {
                        var buttons = [];
                        var itemSelected = getElement();
                        var next = itemSelected.next('.content-files');
                        
                        var selectedButton = itemSelected.find("hyatt-edit-files");
                        var nextButton = next.find("hyatt-edit-files");
                        buttons.push(selectedButton, nextButton);
                        
                        if (next.length > 0) {
                            itemSelected.insertAfter(next);
                            var selectedItemOrderValue = selectedButton.attr('order-value');
                            var nextOrderValue = nextButton.attr('order-value');
                            selectedButton.attr('order-value', nextOrderValue);
                            nextButton.attr('order-value', selectedItemOrderValue);
                            updateOrder(buttons);
                        }
                    };

                    scope.orderActivation = function() {
                        var orderButtons = angular.element(".order-button");

                        for (var i = 0; i < orderButtons.length; i++) {
                            if(!angular.element(orderButtons[i]).hasClass(".change-order-" + scope.buttonId)){
                                angular.element(orderButtons[i]).addClass("ng-hide");
                            }
                        }

                        var orderButton = angular.element(".change-order-" + scope.buttonId);
                        if(orderButton.hasClass("ng-hide")){
                            orderButton.removeClass("ng-hide");
                        } else {
                            orderButton.addClass("ng-hide");
                        }
                    };

                    scope.inputChange = function(){
                        if(scope.label !== ""){
                            scope.buttonName = scope.labelButton;
                        } else {
                            scope.buttonName = scope.label;
                        }
                    };

                    function getElement(){
                        return angular.element(".button-added-"+scope.buttonId).parent();
                    }

                    function updateOrder(buttons){
                        var uploadLoading = angular.element('.file-upload');
                        uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        
                        var changes = buttons;
                        var fileRelationObj = ImagesService.getImageRelationOrderObject(scope.contentId, scope.relatorId, changes[0].attr('button-id'), scope.ctdName, changes[0].attr('order-value'), 'file');
                        fileRelationObj.isApproved = false;
                        ImagesService.postImageChange(fileRelationObj).then(function () {
                            logActivityEdit(fileRelationObj, "EDITED");
                            buttons.shift();
                            if(buttons.length > 0) {
                                setTimeout(function() {
                                    updateOrder(buttons); 
                                }, 1000);
                            } else {
                                ContentsService.getContentById(scope.contentId, '1').then(function () {
                                    uploadLoading.LoadingOverlay("hide", true);
                                    angular.element(".icon-btn").addClass("item-unapproved");
                                    angular.element(".content-status").addClass("item-unapproved");
                                    angular.element(".status-button ").find(".item-options").html("Approve this page");
                                    angular.element(".status-page").html("Unapproved");
                                });
                            }
                        },
                        function (error){
                            uploadLoading.LoadingOverlay("hide", true);
                        });
                    }

                    function updateTitleFiles(newText, oldTextValue, uploadLoading){
                        rootScope.imageObject.parentContentId = scope.contentId;
                        var files = rootScope.imageObject;
                        //uploading new file
                        ImagesService.uploadImage(files).then(function (uploadResponse) {
                            var newFileId = uploadResponse.data.id;
                            var fileRelationObj = ImagesService.getImageRelation(scope.contentId, scope.relatorId, scope.buttonId, scope.ctdName, newFileId, 'file');
                            fileRelationObj.isApproved = false;
                            rootScope.y = window.pageYOffset;
                            //updating file association
                            ImagesService.postImageChange(fileRelationObj).then(function (fileChangeResponse) {
                                logActivityEdit(fileRelationObj, "EDITED");
                                rootScope.imageObject = {};
                                if(newText !== "" && newText !== oldTextValue){
                                    updateTitle(newText, uploadLoading, true);
                                } else{
                                    uploadLoading.LoadingOverlay("hide", true);
                                    angular.element(".modal").modal("hide");
                                }
                                var contentUpload = angular.element(".btn-files-attach");
                                contentUpload.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                                reload();
                                //removeStaticFile(newFileId, contentUpload);
                            },
                            function (error){
                                showError(uploadLoading);
                            });
                        }, 
                        function (error) {
                            showError(uploadLoading);
                        });
                    }

                    function updateTitle(newText, uploadLoading, imageChange){
                        var fileRelationObj = ImagesService.getFileRelationTitleObject(scope.contentId, scope.relatorId, scope.buttonId, scope.ctdName, newText, 'file');
                        //updating new button title
                        fileRelationObj.isApproved = false;
                        ImagesService.postImageChange(fileRelationObj).then(function () {
                           logActivityEdit(fileRelationObj, "EDITED");
                           angular.element(".edit-" + scope.buttonId).val(newText);
                           scope.label = newText;
                           angular.element(".modal").modal("hide");
                           scope.fileName = newText;
                           if(!imageChange){
                            angular.element(".btn-files-attach").LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                            rootScope.y = window.pageYOffset;
                            reload();
                           }
                        }, function (error) {
                           uploadLoading.LoadingOverlay("hide", true);
                           angular.element(".modal").modal("hide");
                           showError(uploadLoading);
                        });
                    }

                    function removeStaticFile(newFileId, uploadLoading){
                        if(scope.fileId !== null && scope.fileId !==undefined &&scope.fileId !== ""){
                            var fileObject = {
                                fileId: scope.fileId
                            };
                            scope.fileId = newFileId;
                            ImagesService.deleteStaticFile(fileObject).then(function (){
                                if(scope.isEdit){
                                    reload();
                                }
                            },
                            function (error){
                                reload();
                            });
                        } else {
                            uploadLoading.LoadingOverlay("hide", true);
                        }
                    }

                    function reload(){
                        setTimeout(function() {
                            ContentsService.getContentById(scope.contentId, '1').then(function () {
                                $state.reload();
                            });
                        }, 1000);
                    }

                    function logActivityEdit(fileRelationObj, actionType){
                        var attributeXmlName = "";
                        if(fileRelationObj.objectsRelation != undefined) {
                            for(var i = 0; i < fileRelationObj.objectsRelation[0].objectsRelation.length; i++){
                                attributeXmlName = fileRelationObj.objectsRelation[0].objectsRelation[i].attributeXmlName;
                            }
                        }
                        LogService.saveView(scope.ctdName, attributeXmlName, fileRelationObj.contentId, actionType);
                    }

                    function logActivityRemove(response, actionType){
                        var attributeXmlName = "";
                        if(response.data.objectsRelation[0] != undefined) {
                            attributeXmlName = response.data.objectsRelation[0].objectsRelation[0].attributeXmlName;
                        }
                        LogService.saveView(scope.ctdName, attributeXmlName, scope.contentId, actionType);
                    }

                    function showError(uploadLoading){
                        rootScope.imageObject = {};
                        uploadLoading.LoadingOverlay("hide", true);
                        angular.element(".modal").modal("hide");
                        $('.panel .alert-danger').fadeIn(500, function (e) {
                            $(this).fadeOut(3000);
                        });
                    }
                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/hyatt-edit-files.html'
            };
}]);

angular.module(moduleName)
    .directive('hyattEditMenu', ['hyattEditConfiguration', '$timeout', '$compile', 'MenusEditService', '$rootScope', '$state', 'ContentsService', 'LogService',
        function (hyattEditConfiguration, $timeout, $compile, MenusEditService, $rootScope, $state, ContentsService, LogService) {
            function link(scope, element, attrs) {

                scope.saveMenuItem = function () {
                    scope.onSave = true;
                    var changes = [];

                    var menuItemTextChange = getMenuItemTextChange();
                    if (menuItemTextChange) {
                        changes.push(menuItemTextChange);
                    }

                    if (scope.itemsMoved) {
                        var menuItemOrderChange = {};
                        menuItemOrderChange.objects = [];
                        menuItemOrderChange.objectsRelation = [];

                        var menuItem = getCurrentMenuItemElement();
                        var menuItems = MenusEditService.getMenuItems(menuItem);

                        if (menuItem.hasClass('section-item')) {
                            menuItemOrderChange.contentId = menuItem.closest('.chapter-item').attr('data-menu-item');
                        } else if (menuItem.hasClass('article-item')) {
                            menuItemOrderChange.contentId = menuItem.closest('.section-item').attr('data-menu-item');
                        }


                        if (menuItem.hasClass('chapter-item')) {

                            menuItems.each(function (index) {
                                var chapterChange = {};
                                chapterChange.objects = [];
                                chapterChange.contentId = $(this).attr('data-menu-item');

                                chapterChange.objects.push({
                                    attributeXmlName: 'BEG-CHAPTER-DISPLAY-ORDER',
                                    attributeValue: $(this).attr('data-order-value'),
                                    type: 'INTEGER'
                                });
                                changes.push(chapterChange);
                            });
                        } else {
                            menuItems.each(function (index) {
                                var relationObj;
                                var menuItemId = $(this).attr('data-menu-item');
                                var orderValue = $(this).attr('data-order-value');

                                if ($(this).hasClass('section-item')) {
                                    relationObj = MenusEditService.getSectionRelationObject();
                                } else if ($(this).hasClass('article-item')) {
                                    relationObj = MenusEditService.getArticleRelationObject();
                                }

                                relationObj.relationId = menuItemId;
                                relationObj.attributeValue = orderValue;
                                menuItemOrderChange.objectsRelation.push(relationObj);
                            });
                            changes.push(menuItemOrderChange);
                        }
                    }
                    postAllChanges(changes);
                };

                scope.moveMenuItemUp = function () {
                    var itemSelected = getCurrentMenuItemElement();
                    MenusEditService.moveMenuItemUp(itemSelected);
                    scope.itemsMoved = MenusEditService.verifyOriginalMenuItemPositions(itemSelected);
                };

                scope.moveMenuItemDown = function () {
                    var itemSelected = getCurrentMenuItemElement();
                    MenusEditService.moveMenuItemDown(itemSelected);
                    scope.itemsMoved = MenusEditService.verifyOriginalMenuItemPositions(itemSelected);
                };

                scope.applyNavigationSortPosition = function () {
                    scope.currentEditor.showArrows = true;
                    scope.currentEditor.textInput = false;
                    scope.removeAddNavigationField();
                };

                scope.toggleNavTextInput = function () {
                    var menuItem = getCurrentMenuItemElement();
                    var nextLink = getNextLinkItem(menuItem);
                    if (!scope.currentEditor.textInput) {
                        scope.currentEditor.textInput = true;
                        scope.currentEditor.showArrows = false;
                        applyInputFocus();
                        nextLink.hide();
                        scope.removeAddNavigationField();
                    } else {
                        scope.currentEditor.textInput = false;
                        nextLink.show();
                    }
                };

                scope.toggleNavArrows = function () {
                    var menuItem = getCurrentMenuItemElement();
                    var nextLink = getNextLinkItem(menuItem);
                    if (!nextLink.is(':visible')) {
                        nextLink.show();
                    }
                    scope.currentEditor.showArrows = true;
                    scope.currentEditor.textInput = false;
                    scope.removeAddNavigationField();
                };

                scope.removeAddNavigationField = function () {
                    angular.element('.current-add-item').remove();
                    scope.currentChapterItem = { name: '' };
                };

                $rootScope.applyAddNewNavigationItemExt = function (menuItemId) {
                    $timeout(function () {
                        menuItem = angular.element('#menu-item-' + menuItemId);
                        scope.applyAddNewChildNavigationItem(menuItem);
                    }, 600);
                };

                scope.applyAddNewChildNavigationItem = function (menuItem) {

                    if (!menuItem) {
                        menuItem = getCurrentMenuItemElement();
                    }

                    if (scope.currentEditor.menuItemType === 'chapter-item') {
                        scope.currentEditor.itemType = 'section-item';
                    } else if (scope.currentEditor.menuItemType === 'section-item') {
                        scope.currentEditor.itemType = 'article-item';
                    }

                    angular.element('.current-add-item').remove();
                    var directive = angular.element('<li>')
                        .append('<hyatt-add-menu-item item-type="currentEditor.itemType" parent-id="currentEditor.id" parent-name="currentEditor.name"></hyatt-add-menu-item>');
                    directive.addClass('current-add-item');
                    var addChildMenuItem = directive;

                    var parentMenuItem = menuItem.find('ul.dropdown-menu:first');
                    if (parentMenuItem.length) {
                        parentMenuItem.append(addChildMenuItem);
                    } else {
                        parentMenuItem.append(addChildMenuItem);
                        parentMenuItem = $('<ul>').addClass('dropdown-menu');
                        menuItem.append(parentMenuItem);
                    }


                    scope.currentEditor.showArrows = false;
                    scope.currentEditor.textInput = false;
                    $compile(addChildMenuItem)(scope);
                    parentMenuItem.slideDown(0);
                };

                scope.applyLinkNewValue = function (newValue) {
                    var selectedItem = getCurrentMenuItemElement();
                    var link = selectedItem.find('.menu-item-link:first');
                    if (newValue) {
                        link.text(newValue);
                    }
                };

                scope.removeAddNavigationField = function () {
                    angular.element('.current-add-item').remove();
                    scope.currentChapterItem = { name: '' };
                };

                scope.showMenuEditWarningModal = function () {
                    angular.element('#menuEditWarning').addClass('in').show();
                };

                scope.toggleSelection = function ($event) {
                    angular.element(".check-all").prop('checked', false);
                    var pageId =  angular.element($event.currentTarget).attr("value");
                    var idx = scope.selection.indexOf(pageId);
                    if (idx > -1) {
                      scope.selection.splice(idx, 1);
                    } else {
                      scope.selection.push(pageId);
                    }
                };

                scope.toggleAll = function ($event) {
                    var isChecked = angular.element($event.currentTarget).prop("checked");
                    if(isChecked) {
                        angular.element(".checkbox-menu-childs").prop('checked', "checked");
                        for (var i = 0; i <= scope.menuChilds.length - 1; i++) {
                            scope.selection.push(scope.menuChilds[i].id);
                        }
                    }
                };

                scope.approveItems = function () {
                    if(scope.selection.length > 0 ) {
                        var sideBar = $('#sidebar');
                        sideBar.LoadingOverlay("show", { image: '/files/beg/images/icons/loading_main.svg' });
                        var contentsParams = {};
                        contentsParams.contentIds = scope.selection;
                        contentsParams.isApprove = true;
                        ContentsService.approveUnapproveContent(contentsParams).then(function () {
                            for (var i = 0; i <= contentsParams.contentIds.length - 1; i++) {
                                ContentsService.getContentById(contentsParams.contentIds[i], '1');
                            }
                            $rootScope.reloadMenu();
                            angular.element("#approveModal").modal('hide');
                            sideBar.LoadingOverlay("hide", true);
                            $state.reload();
                        }, function (error) {
                           sideBar.LoadingOverlay("hide", true);
                            angular.element("#approveModal").modal('hide');
                            $('.panel .alert-danger').fadeIn(500, function () {
                                $(this).fadeOut(2000, function () {
                                    $state.reload();
                                });
                            });
                        });
                    }
                };

                $rootScope.removeMenuItem = function () {

                    var menuItemToRemove = {};
                    var relationObj;

                    var parentElement;
                    var menuItem = getCurrentMenuItemElement();
                    if (scope.currentEditor.menuItemType === 'article-item') {
                        relationObj = MenusEditService.getArticleRelationObject();
                        parentElement = menuItem.closest('.section-item');
                        menuItemToRemove.contentId = parentElement.attr('data-menu-item');
                    } else if (scope.currentEditor.menuItemType === 'section-item') {
                        relationObj = MenusEditService.getSectionRelationObject();
                        parentElement = menuItem.closest('.chapter-item');
                        menuItemToRemove.contentId = parentElement.attr('data-menu-item');
                    }

                    if (!relationObj) {
                        menuItemToRemove.contentId = scope.currentEditor.id;
                    } else {
                        menuItemToRemove.objectsRelation = [];
                        relationObj.relationId = scope.currentEditor.id;
                        menuItemToRemove.objectsRelation.push(relationObj);
                    }
                    var sideBarElement = angular.element('#sidebar');
                    sideBarElement.LoadingOverlay("show", { image: '/files/beg/images/icons/loading_main.svg' });

                    var prevMenuItem = menuItem.prev();
                    ContentsService.deleteContent(menuItemToRemove).then(function (response) {
                        logActivity(menuItemToRemove, menuItemToRemove.contentId, "REMOVED");
                        var menuItemId;
                        if (prevMenuItem.length > 0) {
                            menuItemId = prevMenuItem.attr('data-menu-item');
                        }
                        $rootScope.editionOn = true;
                        $rootScope.reloadMenu(menuItemId);
                    }, function (error) {
                        sideBarElement.LoadingOverlay("hide", true);
                    });
                };

                function getMenuItemTextChange() {
                    var menuItemTextChange;
                    var xmlNameInput = $('#hidden-xml-name-' + scope.currentEditor.id);
                    if (xmlNameInput && scope.currentEditor.id && scope.currentEditor.newValue !== scope.currentEditor.name) {
                        var xmlNameValue = xmlNameInput.val();
                        menuItemTextChange = {};
                        menuItemTextChange.objects = [];
                        menuItemTextChange.contentId = scope.currentEditor.id;
                        var obj = {
                            attributeXmlName: xmlNameValue,
                            attributeValue: scope.currentEditor.newValue
                        };
                        menuItemTextChange.objects.push(obj);
                    }
                    return menuItemTextChange;
                }

                function postAllChanges(changes) {
                    var contentModified = changes.pop();
                    if (contentModified) {
                        var sideBar = $('#sidebar');
                        sideBar.LoadingOverlay("show", { image: '/files/beg/images/icons/loading_main.svg' });
                        ContentsService.updateContent(contentModified).then(function (response) {
                            logActivity(contentModified, response.data.contentId, "EDITED");
                            ContentsService.getContentById(contentModified.contentId, "1");
                            if (changes.length > 0) {
                                postAllChanges(changes);
                            } else {
                                MenusEditService.setOriginalOrderValues(getCurrentMenuItemElement());
                                scope.itemsMoved = MenusEditService.verifyOriginalMenuItemPositions();
                                $('.panel .alert-success').fadeIn(500, function () {
                                    $(this).fadeOut(2000, function () {
                                        $state.reload();
                                    });
                                });


                                sideBar.LoadingOverlay("hide", true);
                                scope.applyLinkNewValue(scope.currentEditor.newValue);
                                scope.currentEditor.textInput = false;
                                scope.currentEditor.name = scope.currentEditor.newValue;
                                scope.onSave = false;

                                var menuItem = getCurrentMenuItemElement();
                                var nextLink = getNextLinkItem(menuItem);
                                nextLink.show();
                                ContentsService.refreshChannel($rootScope.currentBrand.id, '1');
                            }
                        }, function (error) {
                            scope.onSave = false;
                            sideBar.LoadingOverlay("hide", true);
                            $('.panel .alert-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                        });
                    }
                }

                function applyInputFocus() {
                    $timeout(function () {
                        var input = angular.element(element).find('input.edit-menu');
                        input.focus();
                        var tmpStr = input.val();
                        input.val('');
                        input.val(tmpStr);

                    }, 200);
                }

                function getCurrentMenuItemElement() {
                    return angular.element(element).closest('.menu-item');
                }

                function getCurrentMenuItemChilds(menuItem) {
                    return menuItem.find(".dropdown-menu").find(".menu-item");
                }

                function getCurrentMenuItemType(currentItem) {
                    if(currentItem.hasClass('article-item')) {
                        return "article";
                    } else if (currentItem.hasClass('section-item')){
                        return "section";
                    } 
                    return "chapter";
                }

                function getChildContentType(menuItem) {
                    if (menuItem.hasClass('chapter-item')) {
                        return 'chapter-item';
                    } else if (menuItem.hasClass('section-item')) {
                        return 'section-item';
                    } else {
                        return 'article-item';
                    }
                }

                function getNextLinkItem(menuItem) {
                    var linkItem = menuItem.find('a.menu-item-link:first');
                    var linkParent = linkItem.parent();
                    if (linkParent.prop("tagName").toUpperCase() === 'SPAN') {
                        return linkParent;
                    }
                    return linkItem;
                }

                function logActivity(contentModified, id, actionType) {
                    var attributeXmlName = "";
                    var ctdName = "BEG-CHAPTER";       
                    
                    for (var i = 0; i < contentModified.objects.length; i++) {
                        attributeXmlName += contentModified.objects[i].attributeXmlName + ",";
                    }

                    if(attributeXmlName.indexOf("ARTICLE")) {
                        ctdName = "BEG-ARTICLE";
                    } else if(attributeXmlName.indexOf("SECTION")) {
                        ctdName = "BEG-SECTION";
                    }

                    LogService.saveView(ctdName, attributeXmlName, id, actionType);
                }

                function init() {
                    var menuItem = getCurrentMenuItemElement();
                    var menuItemchilds = getCurrentMenuItemChilds(menuItem);
                    if (menuItem.length === 0) {
                        return;
                    }

                    scope.selection = [];
                    scope.currentEditor = {
                        showArrows: false,
                        textInput: false,
                        name: null,
                        newValue: null,
                        type: null
                    };

                    scope.currentEditor.id = menuItem.attr('data-menu-item');

                    var link = menuItem.find('a.menu-item-link:first');
                    scope.currentEditor.name = link.text().trim();
                    scope.currentEditor.newValue = scope.currentEditor.name;


                    scope.itemsMoved = MenusEditService.verifyOriginalMenuItemPositions(menuItem);
                    scope.currentEditor.menuItemType = getChildContentType(menuItem);
                    scope.menuChilds = [];
                    scope.menuItemType = getCurrentMenuItemType(menuItem);

                    if(menuItemchilds !== undefined && menuItemchilds !== null){
                        for (var i = 0; i <= menuItemchilds.length - 1; i++) {
                            var child = {};
                            var currentItem = angular.element(menuItemchilds[i]);
                            var status = currentItem.attr('data-approved-item');
                            child.id = currentItem.attr('data-menu-item');
                            child.lastMod = currentItem.attr('data-last-mod') !== "" ? "Last Modified - " + currentItem.attr('data-last-mod') : "";
                            child.name = currentItem.find('a.menu-item-link:first').text().trim();
                            child.type = getCurrentMenuItemType(currentItem);
                            child.status = status;
                            if(status !== "approved" || (child.type !== 'article' && status === "approved")){
                                if(scope.menuChilds.length > 0) {
                                   var last = scope.menuChilds[scope.menuChilds.length-1];
                                   if(last.type === "section" && last.status === "approved" && child.type !== "article") {
                                    scope.menuChilds.pop();
                                   } 
                                }
                                scope.menuChilds.push(child);
                            }
                        }

                        var checkLastElement = scope.menuChilds[scope.menuChilds.length-1];

                        if(checkLastElement !== undefined && checkLastElement.type === "section" && checkLastElement.status === "approved") {
                            scope.menuChilds.pop();
                        }
                    }

                }

                init();
            }
            return {
                restrict: 'E',
                link: link,
                scope: {
                    contentId: '=contentId'
                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/menu-edit.html'
            };
        }]);

angular.module(moduleName)
    .directive('hyattImageEditor', ['ImagesService', 'ContentsService', 'hyattEditConfiguration', '$q', '$state', '$rootScope', 'LogService', function (ImagesService, ContentsService, hyattEditConfiguration, $q, $state, $rootScope, LogService) {
        return {
            restrict: 'E',
            scope: {
                'contentId': '=contentId',
                'moduleId': '=moduleId',
                'paragraphImage': '=paragraphImage'
            },
            link: function (scope, element, attrs) {
                var inputUploadImage = angular.element(element).find('.input-upload-image');
                inputUploadImage.bind('change', function (event) {
                    
                    scope.imageObject = undefined;
                    var modalImage = angular.element(element).find('.img-upload');

                    var file = this.files[0];

                    if(file.type.indexOf("image") !== -1) {
                        var fileReader = new FileReader();
                        fileReader.onload = function (e) {
                        var data = e.target.result;
                        scope.imageObject = {};
                        scope.imageObject.parentContentId = scope.contentId;
                        scope.imageObject.filename = file.name.toLowerCase().replace(/([\.])/gi, '_' + new Date().getTime() + '.');
                        scope.imageObject.mimeType = file.type;
                        scope.imageObject.imageBytes = data;
                        scope.imageObject.forceStaticFile = false;

                        scope.imagePathValue = e.target.result;
                        hideImageLoading(modalImage);
                        $rootScope.$apply();
                        };
                        fileReader.onprogress = function (data) {
                            if (data.lengthComputable) {
                                var progress = parseInt(((data.loaded / data.total) * 100), 10);

                            }
                        };
                        showImageLoading(modalImage);
                        fileReader.readAsDataURL(file);
                    } else {
                        $('.panel .alert-file-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                    }
                });

                scope.uploadImage = function () {
                    if (scope.imageObject) {
                        scope.uploading = true;
                        var modalImage = angular.element(element).find('.modal-content');
                        showImageLoading(modalImage);
                        ImagesService.uploadImage(scope.imageObject).then(function (uploadResponse) {
                            scope.paragraphImage.imagePath = uploadResponse.data.sourcePath;
                            var newImageId = uploadResponse.data.id;
                            var ctdName = scope.$parent.data.contents.ctdName;
                            var imageRelationObj = ImagesService.getImageRelation(scope.contentId, scope.moduleId, scope.paragraphImage.relationId, ctdName, newImageId, 'image');
                            imageRelationObj.isApproved = false;
                            ImagesService.postImageChange(imageRelationObj).then(function (imageChangeResponse) {
                                var savedRelationId = imageChangeResponse.data.objectsRelation[0].objectsRelation[0].relationId;

                                imageRelationObj = ImagesService.getImageRelationOrderObject(scope.contentId, scope.moduleId, savedRelationId, ctdName, scope.paragraphImage.orderValue, 'image');

                                if (scope.captionValue && scope.captionValue !== scope.paragraphImage.caption) {
                                    var imageRelationCaption = ImagesService.getImageRelationCaption(ctdName, savedRelationId, scope.captionValue.trim(), 'image');
                                    var imageRelationCaptionPosition = ImagesService.getImageRelationCaptionPosition(ctdName, savedRelationId, scope.captionPosition, 'image');
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationCaption);
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationCaptionPosition);
                                }

                                if (scope.textOverlayValue && scope.textOverlayValue !== scope.paragraphImage.textOverlay) {
                                    var imageRelationTextOverlay = ImagesService.getImageRelationTextOverlay(ctdName, savedRelationId, scope.textOverlayValue.trim(), 'image');
                                    var imageRelationTextOverlayPosition = ImagesService.getImageRelationTextOverlayPosition(ctdName, scope.textOverlayPosition, position, 'image');
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationTextOverlay);
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationTextOverlayPosition);
                                }

                                if (scope.linkTo && scope.linkTo !== scope.paragraphImage.linkTo) {
                                    var imageRelationlinkTo = ImagesService.getImageRelationLinkTo(ctdName, savedRelationId, scope.linkTo.trim(), 'image');
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationlinkTo);
                                }

                                imageRelationObj.isApproved = false;
                                ImagesService.postImageChange(imageRelationObj).then(function () {                                    
                                    logActivity(ctdName, imageRelationObj, "CREATED");
                                    if (scope.paragraphImage.id) {
                                        var contentImageToDelete = {
                                            contentId: scope.paragraphImage.id
                                        };
                                        //ContentsService.deleteContent(contentImageToDelete);
                                    }
                                    scope.paragraphImage.id = newImageId;

                                    clearResources();
                                    scope.hideEditImageModal();
                                    hideImageLoading(modalImage);

                                    ContentsService.getContentById(scope.contentId, '1').then(function () {
                                        scope.uploading = false;
                                        $state.reload();
                                    });
                                });
                            }, function (error) {
                                clearResources();
                                hideImageLoading(modalImage);
                                $('.panel .alert-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                            });
                        }, function (error) {
                            clearResources();
                            hideImageLoading(modalImage);
                            $('.panel .alert-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                        });
                    } else if ((scope.captionValue !== null && (scope.captionValue !== scope.paragraphImage.caption || scope.captionPosition !== scope.paragraphImage.captionPosition)) 
                                || (scope.textOverlay !== null && (scope.textOverlay !== scope.paragraphImage.textOverlay || scope.textOverlayPosition !== scope.paragraphImage.textOverlayPosition))) {
                        
                        var imageRelationId = scope.paragraphImage.relationId;
                        if (imageRelationId && imageRelationId.length) {

                            var ctdName = scope.$parent.data.contents.ctdName;
                            var imageRelationObj = ImagesService.getImageRelationOrderObject(scope.contentId, scope.moduleId, imageRelationId, ctdName, scope.paragraphImage.orderValue, 'image');
                            var captionChange = false;
                            
                            if(scope.captionValue !== scope.paragraphImage.caption || scope.captionPosition !== scope.paragraphImage.captionPosition){
                                 var imageRelationCaption = ImagesService.getImageRelationCaption(ctdName, imageRelationId, scope.captionValue.trim(), 'image');
                                 var position = scope.captionValue === "" ? "" : scope.captionPosition;
                                 var imageRelationCaptionPosition = ImagesService.getImageRelationCaptionPosition(ctdName, imageRelationId, position, 'image');
                                 imageRelationObj.objectsRelation[0].objectsRelation = [imageRelationCaption];
                                 imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationCaptionPosition);
                                 captionChange = true;
                            }

                            if(scope.textOverlay !== scope.paragraphImage.textOverlay || scope.textOverlayPosition !== scope.paragraphImage.textOverlayPosition) {
                                var imageRelationTextOverlay = ImagesService.getImageRelationTextOverlay(ctdName, imageRelationId, scope.textOverlayValue.trim(), 'image');
                                var position = scope.textOverlay === "" ? "" : scope.textOverlayPosition;
                                var imageRelationTextOverlayPosition = ImagesService.getImageRelationTextOverlayPosition(ctdName, imageRelationId, position, 'image');
                                if(captionChange) {
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationTextOverlay);
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationTextOverlayPosition);
                                } else {
                                    imageRelationObj.objectsRelation[0].objectsRelation = [imageRelationTextOverlay];
                                    imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationTextOverlayPosition);
                                }
                            }

                            if (scope.linkTo !== undefined && scope.linkTo !== scope.paragraphImage.linkTo) {
                                var imageRelationlinkTo = ImagesService.getImageRelationLinkTo(ctdName, imageRelationId, scope.linkTo.trim(), 'image');
                                imageRelationObj.objectsRelation[0].objectsRelation.push(imageRelationlinkTo);
                            }

                            var modalImage = angular.element(element).find('.modal-content');
                            showImageLoading(modalImage);
                            scope.uploading = true;
                            imageRelationObj.isApproved = false;
                            ImagesService.postImageChange(imageRelationObj).then(function () {
                                var attributeXmlName = "";
                                for (var i = 0; i < imageRelationObj.objectsRelation[0].objectsRelation.length; i++) {
                                    attributeXmlName += imageRelationObj.objectsRelation[0].objectsRelation[i].attributeXmlName + ",";
                                }
                                LogService.saveView(ctdName, attributeXmlName, imageRelationObj.contentId);
                                scope.hideEditImageModal();
                                hideImageLoading(modalImage);
                                ContentsService.getContentById(scope.contentId, '1').then(function () {
                                    $state.reload();
                                    scope.uploading = false;
                                });
                            });
                        }
                    }
                };

                function showImageLoading(targetElement) {
                    targetElement.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                }
                function hideImageLoading(targetElement) {
                    targetElement.LoadingOverlay("hide", true);
                }

                scope.deleteImageItem = function () {
                     scope.hideModalRemoveImage();
                    var ctdName = scope.$parent.data.contents.ctdName;
                    var loadingTarget = angular.element('.panel .modal.loading');
                    loadingTarget.addClass('in').fadeIn();
                    var imageRelationObj = ImagesService.getImageRelation(scope.contentId, scope.moduleId, scope.paragraphImage.relationId, ctdName, scope.paragraphImage.id, 'image');
                    imageRelationObj.isApproved = false;
                    ImagesService.dissociateImageToModule(imageRelationObj)
                        .then(function (response) {
                            logActivity(ctdName, imageRelationObj, "REMOVED");
                            var imageToDelete = {
                                contentId: scope.paragraphImage.id
                            };
                            ContentsService.deleteContent(imageToDelete).then(function () {
                                ContentsService.getContentById(scope.contentId, '1').then(function () {
                                    $state.reload();
                                    loadingTarget.fadeOut();
                                });
                            });
                        }, function (error) {
                             loadingTarget.fadeOut();
                            $('.panel .alert-danger').fadeIn(500, function () { $(this).fadeOut(3000); });
                        });
                };

                scope.browseNewFile = function () {
                    var inputUploadImage = angular.element(element).find('.input-upload-image');
                    setTimeout(function () { inputUploadImage.click(); });
                };

                scope.hideEditImageModal = function () {
                    var imageModalElement = angular.element(element).find('.edit-modal-lg');
                    imageModalElement.removeClass('in').fadeOut('slow', function (e) {
                        clearResources();
                    });
                };

                scope.showEditImageModal = function () {
                    var imageModalElement = angular.element(element).find('.edit-modal-lg');
                    imageModalElement.addClass('in').show();
                    var el = angular.element(".module-content-"+scope.moduleId+" .modal-img-"+scope.paragraphImage.orderValue);
                    var img = el.find("img");
                    el.width(angular.element(img).width());
                    checkInitialPositions();
                };

                scope.hideModalRemoveImage = function () {
                    var modalRemoveImage = angular.element(element).find('.remove-image-warning');
                    modalRemoveImage.removeClass('in').fadeOut();
                };

                scope.showModalRemoveImage = function () {
                    var modalRemoveImage = angular.element(element).find('.remove-image-warning');
                    modalRemoveImage.addClass('in').show();
                };

                scope.setCaptionPosition = function ($event, value) {
                    $event.preventDefault();
                    angular.element(".module-content-"+scope.moduleId+" .box-caption-order-"+scope.paragraphImage.orderValue+" .captions-options").removeClass("active");
                    angular.element($event.currentTarget).addClass("active");
                    scope.captionPosition = value;
                };

                scope.setOverlayPosition = function ($event, value) {
                    $event.preventDefault();
                    angular.element(".module-content-"+scope.moduleId+" .box-title-order-"+scope.paragraphImage.orderValue+" .title-options").removeClass("active");
                    angular.element($event.currentTarget).addClass("active");
                    scope.textOverlayPosition = value;
                };

                scope.openLink = function() {
                    if(scope.linkTo != undefined && scope.linkTo != null && scope.linkTo != '') {
                        window.open(scope.linkTo,"_blank");
                    }
                };

                scope.getImgCLass = function() {
                    if(scope.linkTo != undefined && scope.linkTo != null && scope.linkTo != '') {
                        return "img-link-to";
                    } else {
                        return "img-responsive";
                    }
                };

                function clearResources() {
                    scope.imageObject = undefined;
                    scope.imagePathValue = scope.paragraphImage.imagePath;
                    inputUploadImage.val('');
                }

                function checkInitialPositions() {
                    checkInitialOverlay();
                    checkInitialCaption();
                }

                function checkInitialOverlay() {
                    var overlayOptions = angular.element(".module-content-"+scope.moduleId+" .box-title-order-"+scope.paragraphImage.orderValue+" .title-options");
                    
                    if(scope.paragraphImage.textOverlayPosition == undefined || scope.paragraphImage.textOverlayPosition == "" || scope.paragraphImage.textOverlayPosition == "Left"){
                        setTimeout(function() {overlayOptions[0].click();}, 50);
                    } else {
                        setTimeout(function() {overlayOptions[1].click();}, 50);
                    }
                }

                function checkInitialCaption() {
                    var captionOptions = angular.element(".module-content-"+scope.moduleId+" .box-caption-order-"+scope.paragraphImage.orderValue+" .captions-options");
                    
                    if(scope.paragraphImage.captionPosition == undefined || scope.paragraphImage.captionPosition == "" || scope.paragraphImage.captionPosition == "Left"){
                        setTimeout(function() {captionOptions[0].click();}, 50);
                    } else if (scope.paragraphImage.captionPosition == "Center") {
                        setTimeout(function() {captionOptions[1].click();}, 50);
                    } else {
                        setTimeout(function() {captionOptions[2].click();}, 50);
                    }
                }

                function logActivity(ctdName, imageRelationObj, actionType) {
                    var attributeXmlName = "";
                    if(imageRelationObj.objectsRelation != undefined) {
                        for (var i = 0; i < imageRelationObj.objectsRelation[0].objectsRelation.length; i++) {
                            attributeXmlName += imageRelationObj.objectsRelation[0].objectsRelation[i].attributeXmlName + ",";
                        }
                    }
                    LogService.saveView(ctdName, attributeXmlName, imageRelationObj.contentId, actionType);
                }

                function init() {
                    scope.imagePathValue = scope.paragraphImage.imagePath;
                    scope.captionValue = angular.copy(scope.paragraphImage.caption);
                    scope.textOverlayValue = angular.copy(scope.paragraphImage.textOverlay);
                    scope.textOverlayPosition = angular.copy(scope.paragraphImage.textOverlayPosition);
                    scope.captionPosition = angular.copy(scope.paragraphImage.captionPosition);
                    scope.linkTo = angular.copy(scope.paragraphImage.linkTo);
                }

                init();
            },
            templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/image-edit.html'
        };
    }]);

angular.module(moduleName)
  .directive('hyattInlineText', ['$rootScope', '$window', '$sanitize', '$state', 'ContentsService', 'hyattEditConfiguration', 'LogService',
    function ($rootScope, $window, $sanitize, $state, ContentsService, hyattEditConfiguration, LogService) {
      function link(scope, element, attrs) {

        scope.isApproved = true;
        scope.isOptionClicked = false;

        scope.removeAllEditors = function () {
          tinymce.remove(".tinymce-editor");
        };

        function hideModal() {
          angular.element('#modal-content-' + scope.contentId).removeClass('in').hide();
          angular.element('.modal-overlay').hide();
        }

        function isDirty(editor) {
          var currentContent = angular.element(editor.bodyElement).text();
          var startContent;
          var parse = angular.element(editor.startContent);

          if (editor.startContent.length > 1 && parse.length > 0) {
            startContent = parse.text();
          } else {
            startContent = editor.startContent;
          }
          if ((currentContent === '' && startContent === '')) {
            editor.setContent('');
            editor.setDirty(false);
            return false;
          }
          if (scope.attributeXmlName.indexOf('CONTENT-TITLE') !== -1) {
            if (currentContent === startContent) {
              editor.setDirty(false);
              return false;
            }
          } else {
            if (editor.startContent === editor.getContent({ format: 'raw' })) {
              editor.setDirty(false);
              return false;
            }
          }
          return editor.isDirty();
        }
        
        function verifyEmptyContent(editor) {
          var contentValue = editor.getContent();
          if (editor.getContent() === "") {
            tinymce.DOM.addClass(editor.bodyElement, 'empty');
          } else {
            tinymce.DOM.removeClass(editor.bodyElement, 'empty');
          }
        }

        scope.continueEditing = function () {
          hideModal();
          var currentEditor = tinymce.editors[0];
          if (currentEditor) {
            currentEditor.focus();
          }
        };

        scope.discardChanges = function () {
          var currentEditor = tinymce.editors[0];
          currentEditor.setContent(currentEditor.startContent);
          verifyEmptyContent(currentEditor);
          scope.removeAllEditors();
          hideModal();
        };

        scope.bindAnchors = function () {
          $('.panel a[href^="#"]').on('click', function (e) {
            e.preventDefault();
            var target = this.hash;
            if (target !== null && target !== undefined && target !== "") {
              $target = $(target);
              $('html, body').stop().animate({
                'scrollTop': $target.offset().top
              }, 900, 'swing', function () {
                window.location.hash = target;
              });
            }
          });
        };

        scope.collapseModule = function(isCollapsed) {
          if(isCollapsed == "true" && !angular.element(".edit-box").is(":visible")) {
            var el = angular.element("#module-"+scope.relationId+" .collapse-module");
            if(el.hasClass("collapse-module-close")){
              angular.element("#module-"+scope.relationId).removeClass("remove-height");
              angular.element(el).removeClass("collapse-module-close");
              angular.element(".table-content-"+scope.relationId).show();
            } else {
              angular.element("#module-"+scope.relationId).addClass("remove-height");
              angular.element(el).addClass("collapse-module-close");
              angular.element(".table-content-"+scope.relationId).hide();
            }
            angular.element('.module-content-'+scope.relationId).slideToggle(500);
          }
        };

        scope.getKeywords = function(){
          var keywords = scope.keywords.replace(/,/g, ", ");
          return "keywords: " + keywords;
        };

        scope.applyTinymce = function (target) {

          var editorToolBarTitle = ['save saveapprove options undo redo'];
          var editorToolBar = ['save saveapprove undo redo  | bold italic underline | styleselect | link anchor | alignleft aligncenter alignright | bullist numlist | outdent indent | superscript | code '];
          var forceRootBlock = 'p';
          if (scope.attributeXmlName.indexOf('CONTENT-TITLE') !== -1) {
            editorToolBar = editorToolBarTitle;
            forceRootBlock = false;
          }

          if (!angular.element(target).hasClass('inline-edit-mode')) {
            angular.element(target).addClass('inline-edit-mode');
            tinymce.init({
              target: target,
              element_format: 'html',
              toolbar: editorToolBar,
              forced_root_block: forceRootBlock,
              relative_urls: false,
              browser_spellcheck: true,
              style_formats: [
                {
                  title: 'Headers', items: [
                    { title: 'Header 1', format: 'h1' },
                    { title: 'Header 2', format: 'h2' },
                    { title: 'Header 3', format: 'h3' },
                    { title: 'Header 4', format: 'h4' },
                    { title: 'Header 5', format: 'h5' },
                    { title: 'Header 6', format: 'h6' },
                    { title: 'Body', format: 'p' }
                  ]
                },
              ],

              init_instance_callback: function (editor) {
                editor.on('blur', function (e) {
                  angular.element(element[0].children[0]).show();
                  angular.element(e.target.bodyElement).removeClass('inline-edit-mode');

                  if (isDirty(editor) && !scope.savingContent && !scope.isOptionClicked) {
                    angular.element('#modal-content-' + scope.contentId).addClass('in').show();
                    angular.element('.modal-overlay').show();
                  }

                  if(scope.isOptionClicked){
                    scope.discardChanges();
                  }

                  verifyEmptyContent(editor);
                });
                editor.on('remove', function (e) {
                  angular.element(e.target.bodyElement).removeClass('inline-edit-mode');
                  if (!editor.saved) {
                    editor.bodyElement.innerHTML = editor.startContent;
                  } else {
                    editor.saved = false;
                  }
                });
                editor.on('click', function (e) {
                  if (!angular.element(e.currentTarget).hasClass('inline-edit-mode')) {
                    angular.element(e.currentTarget).addClass('inline-edit-mode');
                  }
                });

              },
              setup: function (editor) {
                function monitorNodeChange() {

                  editor.on('change', function (e) {
                    verifyEmptyContent(this);

                    var as = $(e.target.bodyElement).find('a');
                    as.each(function (item) {
                      var that = this;
                      if (that.innerHTML && that.innerHTML.toLowerCase().indexOf('download') !== -1) {
                        angular.element(that).addClass('downloadbutton');
                      }
                      var hrefAttr = angular.element(this).attr('href');
                      if (hrefAttr && hrefAttr.substring(0, 1) !== '#') {
                        angular.element(this).attr('target', '_blank');
                      }
                    });
                  });
                  editor.on('keyup', function (e) {
                    if ((e.key === "Backspace" || e.keyCode === 8) && editor.getContent({ format: 'text' }) === "") {
                      tinymce.DOM.removeClass(editor.bodyElement, 'empty');
                      return;
                    }
                    verifyEmptyContent(editor);
                  });

                  editor.on('click', function (e) {
                    tinymce.DOM.removeClass(editor.bodyElement, 'empty');
                  });
                }

                editor.on('init', function (e) {
                  tinymce.DOM.removeClass(editor.bodyElement, 'empty');
                  tinyMCE.activeEditor.focus();

                });

                editor.addMenuItem('save', {
                  icon: 'save',
                  cmd: 'mceSave',
                  context: 'file',
                  disabled: true,
                  onPostRender: function () {
                    var self = this;
                    editor.on('nodeChange', function () {
                      self.disabled(editor.getParam("save_enablewhendirty", true) && !editor.isDirty());
                    });
                  }
                });

                editor.addButton('saveapprove', {
                  text: 'Save As Draft',
                  icon: 'save',
                  context: 'file',
                  disabled: true,
                  onclick: function (e) {
                    scope.isApproved = false;
                    editor.execCommand('mceSave', false);
                  },
                  onPostRender: function () {
                    var self = this;
                    editor.on('nodeChange', function () {
                      self.disabled(editor.getParam("save_enablewhendirty", true) && !editor.isDirty());
                    });
                  }
                });

                editor.addButton('options', {
                  text: '',
                  icon: true,
                  image: '/files/beg/images/icon-gear.png',
                  context: 'file',
                  onclick: function (e) {
                    scope.isOptionClicked = true;
                    var el = angular.element(".module-options");
                    if(!el.is(":visible")){
                      angular.element("#tagContainer").find("span").remove();
                      $rootScope.moduleOptions.contentId = scope.contentId;
                      $rootScope.moduleOptions.relationId = scope.relationId;
                      $rootScope.moduleOptions.moduleName = scope.originalValue;
                      $rootScope.moduleOptions.isCollapsed = scope.isCollapsible == "" ? "false" : scope.isCollapsible;

                      var keywords = scope.keywords !== "" ? $sanitize(scope.keywords) : "";
                      keywords = keywords.replace(/&amp;/g,"&");
                      $rootScope.moduleOptions.keywords = keywords == "" ? [] : keywords.split(',');
                      
                      $rootScope.$apply();
                      
                      if($rootScope.moduleOptions.isCollapsed === 'true') {
                        angular.element('.select-collapse input').prop('checked', true);
                      } else {
                        angular.element('.select-collapse input').prop('checked', false);
                      }
                      
                      el.addClass("in");
                      el.show();
                      el.focus();
                      scope.isOptionClicked = false;
                    } else {
                      el.removeClass("in");
                      el.hide();
                    }
                  }
                });
              },

              save_onsavecallback: function (e) {
                saveContent(e);
              },

              plugins: [
                "advlist autolink link anchor image lists hr pagebreak",
                "save code fullscreen media nonbreaking autoresize",
                "template paste spellchecker"
              ],
              height: 200,
              autoresize_min_height: 200,
              menubar: false,
              style_formats_autohide: true,
              link_title: false,
              target_list: false,
              inline: true,
              toolbar_items_size: 'small',

            });
          }
        };

        function saveContent(e){
          var currentEditor = tinyMCE.activeEditor;
          var currentTextContent = currentEditor.bodyElement.innerHTML;
          if (scope.attributeXmlName.indexOf('CONTENT-TITLE') !== -1) {
            currentTextContent = currentEditor.getContent({ format: 'text' }).trim();
          }
          var contentModified = {};
          contentModified.contentId = scope.contentId;
          contentModified.isApproved = scope.isApproved;
          contentModified.objects = [];

          if (!scope.relationId) {
            var obj = {
              attributeXmlName: scope.attributeXmlName,
              attributeValue: currentTextContent
            };
            contentModified.objects.push(obj);
          } else {
            contentModified.objectsRelation = [];
            var relationObj = {};
            relationObj.relationId = scope.relationId;
            relationObj.relationIdXmlName = scope.relationIdXmlName;
            relationObj.relationXmlName = scope.relationXmlName;
            relationObj.attributeXmlName = scope.attributeXmlName;
            relationObj.attributeValue = currentTextContent;
            contentModified.objectsRelation.push(relationObj);
          }
          loadingTarget = angular.element(currentEditor.bodyElement);
          loadingTarget.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing });
          ContentsService.updateContent(contentModified).then(function (response) {
            logActivity("EDITED");
            currentEditor.setContent(currentTextContent);
            currentEditor.startContent = currentEditor.getContent();
            currentEditor.saved = true;

            loadingTarget.LoadingOverlay("hide", true);
            $('.panel .alert-success').fadeIn(500, function () {
              $(this).fadeOut(3000);
            });
            scope.bindAnchors();
            ContentsService.getContentById(scope.contentId, "1").then(function (responseRefresh) {
              scope.savingContent = false;
              $('.panel .alert-success').fadeIn(500, function () {
                $(this).fadeOut(3000);
                approvedContentStyle();
                //standard approved value
                scope.isApproved = true;
                loadingTarget.LoadingOverlay("hide", true);
              });
              if (scope.attributeXmlName.indexOf('CONTENT-TITLE') !== -1 && currentEditor.getContent() === "") {
                $state.reload();
              }
            }, function (error) {
              scope.savingContent = false;
            });
          }, function (responseError) {
            scope.saveError = responseError.statusText;
            scope.saveErrorText = responseError.data.error;
            loadingTarget.LoadingOverlay("hide", true);
            $('.panel .alert-danger').fadeIn(500, function (e) {
              $(this).fadeOut(3000);
            });
          });
        }

        function getUnwrapTrustedValueRawText(originalValue) {
          if (originalValue.$$unwrapTrustedValue) {
            return originalValue.$$unwrapTrustedValue();
          }
          return originalValue;
        }

        function setPlaceholderValue() {
          scope.placeholderValue = 'Insert ' + scope.propertyName + ' text here';
        }

        function approvedContentStyle(){
          if(scope.isApproved) {
            angular.element(".icon-btn").removeClass("item-unapproved");
            angular.element(".content-status").removeClass("item-unapproved");
            angular.element(".status-button ").find(".item-options").html("Unapprove this page");
            angular.element(".status-page").html("Approved");
          } else {
            angular.element(".icon-btn").addClass("item-unapproved");
            angular.element(".content-status").addClass("item-unapproved");
            angular.element(".status-button ").find(".item-options").html("Approve this page");
            angular.element(".status-page").html("Unapproved");
          }
        }
        
        scope.startEdition = function ($event) {
          var target = element[0].children[1];
          scope.removeAllEditors();
          scope.applyTinymce(target);
        };

        function init() {
          scope.originalValueRawText = getUnwrapTrustedValueRawText(scope.originalValue);
          setPlaceholderValue();
        }

        function logActivity(actionType){
            var ctdName = "BEG-CHAPTER";
            if(scope.attributeXmlName.indexOf("ARTICLE")) {
              ctdName = "BEG-ARTICLE";
            }  else if(scope.attributeXmlName.indexOf("SECTION")) {
              ctdName = "BEG-SECTION";
            }

            LogService.saveView(ctdName, scope.attributeXmlName, scope.contentId, actionType);
        }

        init();
      }

      return {
        transclude: true,
        restrict: 'E',
        scope: {
          'contentId': '=contentId',
          'relationId': '=relationId',
          'relationIdXmlName': '=relationIdXmlName',
          'relationXmlName': '=relationXmlName',
          'attributeXmlName': '=attributeXmlName',
          'originalValue': '=originalValue',
          'propertyName': '=propertyName',
          'isCollapsible': '=isCollapsible',
          'keywords': '=keywords'
        },
        link: link,
        templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/edit-inline-text.html'
      };
    }]);
angular.module(moduleName)
    .directive('hyattMenuEditOptions', ['$rootScope', '$state', 'ContentsService', '$compile', 'MenusEditService', 'hyattEditConfiguration', '$timeout', 'UtilInlineService',
        function (rootScope, $state, ContentsService, $compile, MenusEditService, hyattEditConfiguration, timeout, UtilInlineService) {
            return {
                restrict: 'E',
                scope: {
                    'contents': '=contents',
                },
                link: function (scope, element, attrs) {

                    var isChrome = /Chrome/.test(navigator.userAgent) && /Google Inc/.test(navigator.vendor);

                    scope.isServicePortal = isServicePortal();
                    scope.isChapter = false; // initialize
                    timeout(function() { scope.isChapter = isChapter();}, 100);

                    scope.openInlineEditor = function ($event) {
                        var search = angular.element(".container").find("#selectedTerm");
                        if (search.length > 0) {
                            angular.element('#editWarning').addClass('in').show();
                            angular.element('.modal-overlay').show();
                            angular.element('.edit-modal').hide();
                        } else {
                            var inlineEditor = angular.element(".edit-box");
                            if (!inlineEditor.is(":visible")) {
                                switchItemSelected($event);
                                inlineEditor.removeClass('ng-hide');
                                angular.element('.content-editor.empty').removeClass('ng-hide');
                                rootScope.inlineEditorOn = true;
                            }
                        }
                    };

                    scope.openCMSEditor = function ($event) {
                        switchItemSelected($event);

                        var data = scope.contents;
                        var objectId = null;
                        if (data.ctdName === 'BEG_ARTICLE') {
                            objectId = "b56c3d2aea475510VgnVCM1000002031a00a____";
                        } else if (data.ctdName === 'BEG_SECTION') {
                            objectId = "b76c3d2aea475510VgnVCM1000002031a00a____";
                        } else {
                            objectId = "1571366e62ca5510VgnVCM1000002031a00a____";
                        }
                        var contentInstance = vui.vcm.type.CONTENT_INSTANCE;
                        vui.vcm.ui.editor.edit({ asObjectType: contentInstance, objectTypeId: objectId, objectTypeXmlName: data.ctdName, id: data.id });
                    };

                    scope.enableManageParagraphs = function ($event) {
                        switchItemSelected($event);
                        var paragraphEditorElement = angular.element('.edit-module');
                        if (paragraphEditorElement.hasClass("ng-hide")) {
                            switchItemSelected($event);
                            rootScope.paragraphEditorOn = true;
                            paragraphEditorElement.removeClass('ng-hide');
                            angular.element(".panel .img-responsive").removeClass('zoomify').unbind('click');
                        }
                    };

                    scope.enableMoveParagraphPanel = function ($event) {
                        scope.enableManageParagraphs($event);
                        angular.element('.module-move').removeClass('ng-hide');
                        angular.element('.module-trash').addClass('ng-hide');
                        angular.element('.module-change').addClass('ng-hide');
                        angular.element('.module-item').addClass('module-item-margin');
                        rootScope.paragraphMoveOne = true;
                        rootScope.paragraphDeleteOne = false;
                    };

                    scope.enableDeleteParagraphPanel = function ($event) {
                        scope.enableManageParagraphs($event);
                        angular.element('.module-trash').removeClass('ng-hide');
                        angular.element('.module-change').removeClass('ng-hide');
                        angular.element('.module-move').addClass('ng-hide');
                        angular.element('.module-item').addClass('module-item-margin');
                        rootScope.paragraphDeleteOne = true;
                        rootScope.paragraphMoveOne = false;
                    };

                    scope.enableAddParagraphs = function ($event) {
                        switchItemSelected($event);
                        var addFilesBtn = angular.element('.add-module-btn');
                        addFilesBtn.removeClass('ng-hide');
                      /*   if (!isChrome & !rootScope.paragraphAdd) {
                            var scroll2 = $(addFilesBtn[0]).offset().top * 2 + 150;
                            $("html, body").animate({ scrollTop: '+=' + scroll2 }, "fast");
                        } */
                        rootScope.paragraphAdd = true;
                        rootScope.paragraphEditorOn = true;
                    };

                    scope.enableAddFiles = function ($event) {
                        switchItemSelected($event);
                        angular.element(".file-upload").addClass('add-border-file');
                        angular.element(".box-bts-file").removeClass('ng-hide');
                        angular.element(".edit-file-section").removeClass('ng-hide');
                        angular.element(".edit-files-title").removeClass('ng-hide');
                        /* if (!isChrome & !rootScope.fileAdd) {
                            setTimeout(function() {
                                var scroll2 = $($(".file-upload")[0]).offset().top / 2 + 150;
                                if(parseInt(scroll2) > 300){
                                    $("html, body").animate({ scrollTop: '+=' + scroll2 }, "fast"); 
                                }
                            }, 200);
                        } */
                        rootScope.fileAdd = true;
                        rootScope.paragraphEditorOn = true;
                    };

                    scope.openResourceForm = function($event) {
                        angular.element(".overlay-resource").addClass("active");
                    };

                    scope.openResourceEdit = function($event) {
                        angular.element(".resource-note__edit").removeClass("ng-hide");
                    };

                    scope.enableEditNavigation = function ($event) {
                        switchItemSelected($event);
                        var contentId = scope.contents.id;
                        rootScope.editionOn = true;
                        rootScope.applyEditorToMenuItem(contentId);
                        if (rootScope.parentOfLastMenuItemSaved) {
                            rootScope.applyAddNewNavigationItemExt(rootScope.parentOfLastMenuItemSaved);
                            rootScope.parentOfLastMenuItemSaved = undefined;
                        }
                    };

                    scope.clearCache = function () {
                        removeAllEditors();
                        //reload menu
                        rootScope.reloadMenu();
                        //reload content
                        //reload content
                        ContentsService.getContentById(scope.contents.id, '1').then(function () {
                            $state.reload();
                        });
                    };

                    scope.stopEditing = function () {
                        removeAllEditors();
                        angular.element('.btn-edit-active').removeClass('btn-edit-active');
                        angular.element(".overlay-resource").removeClass("active");
                        angular.element(".resource-note__edit").addClass("ng-hide");
                    };

                    scope.approveUnapproveContent = function () {
                        var loadingTarget = angular.element('body');
                        loadingTarget.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing });
                        var contentsParams = {};
                        contentsParams.contentIds = [scope.contents.id];
                        contentsParams.isApprove = false;

                        if(angular.element('.content-status').hasClass('item-unapproved')){
                            contentsParams.isApprove = true;
                        }

                        ContentsService.approveUnapproveContent(contentsParams).then(function () {
                            loadingTarget.LoadingOverlay("hide", true);
                            ContentsService.getContentById(scope.contents.id, '1').then(function () {
                                rootScope.reloadMenu();
                                loadingTarget.LoadingOverlay("hide", true);
                                $('.panel .alert-success').fadeIn(500, function () {
                                    setTimeout(function() {$state.reload();}, 2000);
                                });
                            });
                        }, function (error) {
                            loadingTarget.removeClass('in').fadeOut();
                            angular.element('.panel .alert-danger').fadeIn(500, function () { angular.element(this).fadeOut(3000); });
                        });
                    };

                    scope.toggleMenuEditOptions = function () {
                        scope.isClosed = scope.isClosed ? false : true;
                        var editDiv = angular.element('#edit-contents-container #edit-contents');
                        var that = angular.element('#edit-contents-container');
                        if (that.hasClass('active')) {
                            that.removeClass('active');
                            that.removeClass('priority-open');
                            editDiv.removeClass('active');
                        } else {
                            that.addClass('active');
                            that.addClass('priority-open');
                            editDiv.addClass('active');
                        }
                    };

                    scope.getStatus = function(){
                        if(scope.contents != null && scope.contents != undefined && scope.contents.contentStatus === "approved") {
                            return "Approved";
                        } else {
                            return "Unapproved";
                        }
                    };

                    scope.getStatusButton = function(){
                        if(scope.contents != null && scope.contents != undefined && scope.contents.contentStatus === "approved") {
                            return "Unapprove this page";
                        } else {
                            return "Approve this page";
                        }
                    };

                    function removeAllEditors() {
                        disableManageParagraphs();
                        disableTinyEditor();
                        disableEditNavigation();
                        disableAddFiles();
                    }

                    rootScope.applyEditorToMenuItem = function (contentId) {
                        if (!contentId) {
                            var path = $location.path();
                            var paths = path.split('/');
                            contentId = paths[paths.length - 1];
                        }

                        angular.element('.current-add-item').remove();
                        angular.element('.current-menu-editor').remove();
                        angular.element('.menu-item-link').show();
                        angular.element('.menu-item-link').parent().show();

                        var menuEditor = angular.element('<div>').append('<hyatt-edit-menu content-id="contentId"></hyatt-edit-menu>');
                        menuEditor.addClass('current-menu-editor');

                        var menuItem = angular.element('#menu-item-' + contentId);
                        var menuItemLink = menuItem.find('.menu-item-link:first');

                        var menuItemLinkParentTagName = menuItemLink.parent().prop("tagName");
                        if (menuItemLinkParentTagName.toUpperCase() === 'SPAN') {
                            menuEditor.insertBefore(menuItemLink.parent());
                        } else {
                            menuEditor.insertBefore(menuItemLink);
                        }
                        if (menuEditor.hasClass('none')) {
                            menuEditor.removeClass('none');
                        }

                        $compile(menuEditor)(rootScope);
                        var addMenuItemChapter = angular.element('.add-childMenu.add-chapter');
                        if (addMenuItemChapter.length === 0) {
                            var levelZeroItem = angular.element('<div>');
                            levelZeroItem.append('<hyatt-add-menu-item item-type="\'chapter-item\'"></hyatt-add-menu-item>');
                            $compile(levelZeroItem)(rootScope);
                            angular.element('.nav.navbar-nav').append(levelZeroItem);
                        } else {
                            addMenuItemChapter.show();
                        }
                    };

                    rootScope.remainEditors = function () {
                        if (rootScope.inlineEditorOn) {
                            scope.openInlineEditor();
                            if (tinymce.editors.length > 0) {
                                angular.forEach(tinymce.editors, function (item) {
                                    tinymce.remove(item);
                                });
                            }
                            scope.toggleMenuEditOptions();
                            angular.element('.edit-contents-button.opt-edit-inline').addClass('btn-edit-active');
                        }
                        if (rootScope.paragraphEditorOn) {
                            scope.toggleMenuEditOptions();
                            if (rootScope.paragraphMoveOne) {
                                scope.enableMoveParagraphPanel();
                                angular.element('.edit-contents-button.opt-move-paragraph').addClass('btn-edit-active');
                            } else if (rootScope.paragraphDeleteOne) {
                                angular.element('.edit-contents-button.opt-delete-paragraph').addClass('btn-edit-active');
                                scope.enableDeleteParagraphPanel();
                            } else if (rootScope.paragraphAdd) {
                                angular.element('.edit-contents-button.opt-add-paragraph').addClass('btn-edit-active');
                                scope.enableAddParagraphs();
                            } else if(rootScope.fileAdd) {
                                angular.element('.edit-contents-button.opt-add-files').addClass('btn-edit-active');
                                scope.enableAddFiles();
                            }
                        }
                        var navEditorIsVisible = $('.editMenuAll').is(':visible');
                        if (rootScope.editionOn && !navEditorIsVisible) {
                            scope.enableEditNavigation();
                            scope.toggleMenuEditOptions();
                            angular.element('.edit-contents-button.opt-edit-navigation').addClass('btn-edit-active');
                        } else if (rootScope.editionOn) {
                            scope.toggleMenuEditOptions();
                            angular.element('.edit-contents-button.opt-edit-navigation').addClass('btn-edit-active');
                        }
                    };

                    function disableAddParagraphs() {
                        var addModuleBtn = angular.element('.add-module-btn');
                        if(!addModuleBtn.hasClass('ng-hide')){
                            addModuleBtn.addClass('ng-hide');
                        }
                        var fileSection = angular.element(".edit-file-section");
                        if(!fileSection.hasClass('ng-hide')){
                            fileSection.addClass('ng-hide');
                        }
                        rootScope.paragraphAdd = false;
                    }

                    function disableMoveParagraphPanel() {
                        angular.element('.module-move').addClass('ng-hide');
                        angular.element('.module-item').removeClass('module-item-margin');
                        rootScope.paragraphMoveOne = false;
                    }

                    function disableDeleteParagraphPanel() {
                        angular.element('.module-trash').addClass('ng-hide');
                        angular.element('.module-change').addClass('ng-hide');
                        angular.element('.module-item').removeClass('module-item-margin');
                        rootScope.paragraphDeleteOne = false;
                    }

                    function disableManageParagraphs(paragraphEditorElement) {
                        if (paragraphEditorElement === undefined) {
                            paragraphEditorElement = angular.element('.edit-module');
                        }
                        rootScope.paragraphEditorOn = false;
                        paragraphEditorElement.addClass('ng-hide');
                        disableAddParagraphs();
                        disableMoveParagraphPanel();
                        disableDeleteParagraphPanel();
                    }

                    function disableTinyEditor(inlineEditor) {
                        if (inlineEditor === undefined) {
                            inlineEditor = angular.element(".edit-box");
                        }
                        angular.element('.content-editor.empty').addClass('ng-hide');
                        inlineEditor.addClass('ng-hide');
                        removeTinyEditor();
                        rootScope.inlineEditorOn = false;
                    }

                    function disableEditNavigation() {
                      var positionModified = MenusEditService.verifyOriginalMenuItemPositions();
                      if (positionModified) {
                          rootScope.reloadMenu();
                      }
                      rootScope.editionOn = false;
                      angular.element('.current-add-item').remove();
                      angular.element('.current-menu-editor').remove();
                      angular.element('.add-childMenu.add-chapter').hide();
                    }

                    function disableAddFiles(){
                        angular.element(".file-upload").removeClass('add-border-file');
                        angular.element(".box-bts-file").addClass('ng-hide');
                        angular.element(".order-button").addClass('ng-hide');
                        angular.element(".edit-files-title").addClass('ng-hide');
                        rootScope.fileAdd = false;
                    }

                    function removeTinyEditor() {
                        angular.forEach(tinymce.editors, function (item) {
                            tinymce.remove(item);
                        });
                    }

                    function clickOutEditNavigation() {
                        $(document).click(function (e) {

                            var menuEditOptions = angular.element('#edit-contents-container');
                            var sidebar = angular.element("#sidebar");
                            var editMenuWarningModal = angular.element("#menuEditWarning");
                            var addChildInput = angular.element('.editMenuAll .add-childMenu');
                            if (!sidebar.is(e.target) && sidebar.has(e.target).length === 0 &&
                                !menuEditOptions.is(e.target) && menuEditOptions.has(e.target).length === 0 &&
                                !addChildInput.is(e.target) && addChildInput.has(e.target).length === 0 &&
                                !editMenuWarningModal.is(e.target) && editMenuWarningModal.has(e.target).length === 0) {
                                disableEditNavigation();
                                angular.element('.edit-contents-button.opt-edit-navigation').removeClass('btn-edit-active');
                                rootScope.$apply();
                            }
                        });
                    }

                    function isServicePortal() {
                        var path = window.location.href.split("/");
                        if(path.length >=7 && (path[6] == "serviceportal" || path[6] == "ca")) {
                            return true;
                        } else {
                            return false;
                        }
                    }

                    function isChapter(){
                        var path = window.location.href.split("/");
                        var idArrays = UtilInlineService.getChaptersId();
                        var id = path[path.length - 1];
                        if(idArrays.indexOf(id) != -1) {
                            return true; 
                        } else {
                            return false;
                        }
                    }


                    function switchItemSelected($event) {
                        removeAllEditors();
                        if ($event === undefined) {
                            return;
                        }
                        angular.element('.btn-edit-active').removeClass('btn-edit-active');
                        angular.element($event.currentTarget).addClass('btn-edit-active');
                    }

                    function init() {
                        clickOutEditNavigation();
                    }

                    init();
                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/menu-edit-options.html'
            };
        }]);

angular.module(moduleName)
  .directive('hyattModuleEdit', ['ContentsService', 'hyattEditConfiguration', '$state', 'ContentsEditModuleService',
    '$location', '$rootScope', '$timeout', 'LogService',
    function (ContentsService, hyattEditConfiguration, $state, ContentsEditModuleService, $location, $rootScope, $timeout, LogService) {


      function link(scope, element, attrs) {



        function clearContentCache(contentId) {
          return ContentsService.getContentById(contentId, "1");
        }

        function verifyOriginalModuleItemPositions(moduleItems) {
          var moduleMoved = false;
          moduleItems.each(function (index) {
            var currentPosition = angular.element(this).attr('data-order-value');
            var originalPosition = angular.element(this).attr('data-original-order-value');
            if (currentPosition !== originalPosition) {
              moduleMoved = true;
            }
          });
          return moduleMoved;
        }

        function postModulesChange(contentObj) {
          //var loadingTarget =  angular.element('.panel').parent().LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing });
          var loadingTarget = angular.element('.panel .modal.loading');
          loadingTarget.addClass('in').fadeIn();
          contentObj.isApproved = false;
          ContentsService.updateContent(contentObj).then(function (response) {
            logActivity(contentObj, "EDITED");
            clearContentCache(contentObj.contentId).then(function (resp) {
              $state.reload();
              // loadingTarget.LoadingOverlay("hide", true);
              loadingTarget.removeClass('in').fadeOut();
              angular.element('.panel .alert-success').fadeIn(500, function () { angular.element(this).fadeOut(3000); });
            });
          }, function (error) {

            loadingTarget.removeClass('in').fadeOut();
            angular.element('.panel .alert-danger').fadeIn(500, function () { angular.element(this).fadeOut(3000); });
          });
        }

        function prePostModulesPositionChange() {
          var path = $location.path();
          var paths = path.split('/');
          var contentId = paths[paths.length - 1];

          var ctdName = scope.$parent.data.contents.ctdName;

          var modules = angular.element('.module-item');
          var amountOfModules = modules.length;
          var hasModuleMoved = verifyOriginalModuleItemPositions(modules);
          if (hasModuleMoved) {
            var contentObj = {};
            contentObj.contentId = contentId;
            contentObj.objectsRelation = [];

            modules.each(function (index) {
              var relationId = angular.element(this).attr('data-module-item');
              if (relationId && relationId !== '') {
                var attributeValue = angular.element(this).attr('data-order-value');
                var relationObj = ContentsEditModuleService.getModuleRelationContentDisplayOrder(ctdName, relationId, attributeValue);
                contentObj.objectsRelation.push(relationObj);
              }
            });
            postModulesChange(contentObj);
          }
        }

        function postUpdateModuleReOrder() {

          var path = $location.path();
          var paths = path.split('/');
          var contentId = paths[paths.length - 1];

          var ctdName = scope.$parent.data.contents.ctdName;

          var contentObj = {};
          contentObj.contentId = contentId;
          contentObj.objectsRelation = [];
          var modules = angular.element('.module-item');
          modules.each(function (index) {
            var relationId = angular.element(this).attr('data-module-item');
            var attributeValue = index + 1;
            if (relationId && relationId !== '') {
              var relationObj = ContentsEditModuleService.getModuleRelationContentDisplayOrder(ctdName, relationId, attributeValue);
              contentObj.objectsRelation.push(relationObj);
            }
          });
          contentObj.isApproved = false;
          return ContentsService.updateContent(contentObj);
        }

        function fadeOutFadeIn(target, scroll) {
          if (scroll) {
            angular.element("html, body").animate({ scrollTop: angular.element(target).offset().top }, "slow");
          }
          angular.element(target).fadeOut(500, function () {
            angular.element(this).fadeIn(1000);
          });
        }


        function getModuleElement(moduleId) {
          return angular.element('#module-' + moduleId);
        }

        scope.changeModuleType = function (moduleTypeValue, $event) {

          var newModuleChange = {};
          newModuleChange.contentId = scope.contentId;
          newModuleChange.objectsRelation = [];

          scope.moduleType = moduleTypeValue;
          scope.ctdName = scope.$parent.data.contents.ctdName;
          var relationNewTypeObj = ContentsEditModuleService.getModuleRelationModuleType(scope.ctdName, scope.moduleId, scope.moduleType);
          newModuleChange.objectsRelation.push(relationNewTypeObj);
          scope.optionOn.toggle('slide', {direction: 'left'}, 500, function(){
            $("#module-" + scope.moduleId).children().eq(1).children().eq(0).children().show();
            postModulesChange(newModuleChange);
          });
        };

        scope.moveModuleDown = function () {
          var currentModule = getModuleElement(scope.moduleId);
          var next = currentModule.next('.module-item');
          if (next.length > 0) {
            angular.element('.btn-edit-right').removeClass('inactive-save');
            currentModule.insertAfter(next);
            var selectedItemOrderValue = currentModule.attr('data-order-value');
            var nextOrderValue = next.attr('data-order-value');
            currentModule.attr('data-order-value', nextOrderValue);
            next.attr('data-order-value', selectedItemOrderValue);

            fadeOutFadeIn(next, false);
            fadeOutFadeIn(currentModule, true);
            prePostModulesPositionChange();
          }
        };

        scope.moveModuleUp = function () {
          var currentModule = getModuleElement(scope.moduleId);
          var previous = currentModule.prev('.module-item');
          if (previous.length > 0) {
            angular.element('.btn-edit-right').removeClass('inactive-save');
            currentModule.insertBefore(previous);
            var selectedItemOrderValue = currentModule.attr('data-order-value');
            var previousOrderValue = previous.attr('data-order-value');
            currentModule.attr('data-order-value', previousOrderValue);
            previous.attr('data-order-value', selectedItemOrderValue);

            fadeOutFadeIn(previous, false);
            fadeOutFadeIn(currentModule, true);
            prePostModulesPositionChange();
          }
        };

        scope.deleteModuleItem = function () {

          var moduleToRemove = {};
          moduleToRemove.contentId = scope.contentId;
          var relationObj = {};

          relationObj.relationIdXmlName = scope.relationIdXmlName;
          relationObj.relationXmlName = scope.relationXmlName;
          relationObj.attributeXmlName = scope.attributeXmlName;
          relationObj.relationId = scope.moduleId;

          moduleToRemove.objectsRelation = [];
          moduleToRemove.objectsRelation.push(relationObj);

          var loadingTarget = angular.element('.panel .modal.loading');
          loadingTarget.addClass('in').fadeIn();
          ContentsService.deleteContent(moduleToRemove).then(function (response) {
            var moduleElement = getModuleElement(scope.moduleId);
            moduleElement.fadeOut(300).remove();
            removeModuleImages();
            clearContentCache(scope.contentId).then(function (resp) {
              postUpdateModuleReOrder().then(function (resp) {
                clearContentCache(scope.contentId).then(function (resp) {

                  loadingTarget.removeClass('in').fadeOut();
                  ContentsService.refreshChannel($rootScope.currentBrand.id, '1');
                  $state.reload();
                  $timeout(function () {
                    angular.element('.panel .alert-success').fadeIn(500, function () { angular.element(this).fadeOut(3000); });
                  }, 500);
                });

              });
            });

          }, function (error) {
            loadingTarget.removeClass('in').fadeOut();
            angular.element('.panel .alert-danger').fadeIn(500, function () { angular.element(this).fadeOut(3000); });
          });

        };


        function removeModuleImages() {
          var imageToRemoveId = [];
          ContentsService.getContentById(scope.contentId, null).then(function (response) {
            angular.forEach(response.data.paragraphs, function (paragraph) {
              if (paragraph.relationId === scope.moduleId) {
                if (paragraph.paragraphImages && paragraph.paragraphImages.length > 0) {
                  for (var i = 0; i < paragraph.paragraphImages.length; i++) {
                    imageToRemoveId.push(paragraph.paragraphImages[i].id);
                  }
                  removeImages(imageToRemoveId);
                }
              }
            });
          });
        }

        function removeImages(imageIds) {
          if (imageIds.length > 0) {
            ContentsService.deleteContentList(imageIds);
          }
        }

        scope.closeTemplatePanel = function (panel) {
          if (!panel) {
            panel = angular.element('#panel-' + scope.moduleId);
          }
          panel.hide();
          scope.panelOn = false;
        };

        scope.toggleTemplatePanel = function ($event) {
          angular.element('a.icon-diagram.open').removeClass('open');
          var panel = angular.element('#panel-' + scope.moduleId);
          if (panel.is(':visible')) {
            scope.closeTemplatePanel(panel);
          } else {
            panel.show();
            angular.element($event.currentTarget).addClass('open');
            scope.panelOn = true;
          }
        };

        scope.toggleDeleteModule = function($event){
          var panelDelete = angular.element("#panelDelete--" + scope.moduleId);
          var target = $($event.currentTarget).parent();
          if(!scope.optionOn){
            target.addClass('item-selected');
            scope.itemSelected = target;
            scope.optionOn = panelDelete;
            scope.optionOn.fadeIn();
          }
        };

        scope.toggleChangeModule = function($event){
          var panelChange = angular.element("#panelChange--" + scope.moduleId);
          var target = $($event.currentTarget).parent();
          if(!scope.optionOn){
            target.addClass('item-selected');
            scope.itemSelected = target;
            scope.optionOn = panelChange;
            scope.optionOn.fadeIn();
          }
        };

        scope.closeOptionModule = function(){
          if(scope.optionOn){
            scope.optionOn.fadeOut(function(){
              scope.itemSelected.removeClass('item-selected');
            });
            scope.optionOn = null;
          }
        };

        function logActivity(contentObj, actionType){
            var attributeXmlName = "";
            for (var i = 0; i < contentObj.objectsRelation.length; i++) {
                attributeXmlName += contentObj.objectsRelation[i].attributeXmlName + ",";
            }
            LogService.saveView(scope.$parent.data.contents.ctdName, attributeXmlName, contentObj.contentId, actionType);
        }

        function init() {
          scope.moduleTypeValues = hyattEditConfiguration.default.moduleTypeValues;
        }

        init();

      }

      return {
        transclude: true,
        restrict: 'E',
        scope: {
          'contentId': '=contentId',
          'moduleId': '=moduleId',
          'relationIdXmlName': '=relationIdXmlName',
          'relationXmlName': '=relationXmlName',
          'attributeXmlName': '=attributeXmlName',
          'index': '=index'
        },
        link: link,
        templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/module-edit.html'

      };
    }]);

angular.module(moduleName)
    .directive('hyattModuleOptions', ['ContentsService', '$state', '$rootScope', '$timeout', 'hyattEditConfiguration', '$compile', 'ContentsEditModuleService',
        function (ContentsService, $state, rootScope, $timeout, hyattEditConfiguration, $compile, ContentsEditModuleService) {
            return {
                restrict: 'E',
                scope: {},
                link: function (scope, element, attrs) {

                    scope.addRemoveCollapse = function ($event) {
                        rootScope.moduleOptions.isCollapsed = angular.element($event.currentTarget).is(':checked').toString();
                    };

                    scope.savePreferences = function(approve){
                        var uploadLoading = angular.element('.modal-content');
                        uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        var keyWords = "";
                        var tags = angular.element("#tagContainer").find("span");
                        for (var i = 0; i < tags.length; i++) {
                            keyWords += tags[i].innerText + ",";
                        }

                        if(keyWords.charAt(keyWords.length - 1) == ',') {
                            keyWords = keyWords.replace(/,$/, "");
                        }

                        var moduleOptionsObject = {};
                        moduleOptionsObject.contentId = rootScope.moduleOptions.contentId;
                        moduleOptionsObject.objectsRelation = [];

                        var relationModuleOptionsCollapsed = ContentsEditModuleService.getModuleRelationModuleCollapsed(rootScope.currentContentType, rootScope.moduleOptions.relationId, rootScope.moduleOptions.isCollapsed);
                        moduleOptionsObject.objectsRelation.push(relationModuleOptionsCollapsed);
                        var relationModuleOptionsKeyWords = ContentsEditModuleService.getModuleRelationModuleKeywords(rootScope.currentContentType, rootScope.moduleOptions.relationId, keyWords);
                        moduleOptionsObject.objectsRelation.push(relationModuleOptionsKeyWords);

                        moduleOptionsObject.isApproved = approve;
                        
                        ContentsService.updateContent(moduleOptionsObject).then(function (response) {
                            uploadLoading.LoadingOverlay("hide", true);
                            updateSuccess();
                        }, function (error) {
                           uploadLoading.LoadingOverlay("hide", true);
                           angular.element(".modal").modal("hide");
                           $('.panel .alert-danger').fadeIn(500, function (e) {
                              $(this).fadeOut(3000);
                            });
                        });
                    };

                    scope.hideEditImageModal = function(){
                        var el = angular.element(".module-options");
                        el.removeClass("in");
                        el.hide();
                        rootScope.moduleOptions.keywords = [];
                    };

                    scope.addKeyWord = function(isAdd){
                        var el = angular.element(".module-options #inputText");
                        if (event.which == 13 || isAdd) {
                            event.preventDefault();
                            var keyWord = angular.element(el).val();
                            fillKeyWord(keyWord);
                            angular.element(el).val("");
                        }
                    };

                    scope.removeWord = function($event){
                        var el = angular.element($event.currentTarget).parent().parent();
                        angular.element(el).remove();
                    };

                    function fillKeyWord(keyWord) {
                        var tag = '<span class="tag">' + keyWord + '<a><i ng-click="removeWord($event)" class="remove glyphicon glyphicon-remove"></i></a>  </span>';
                        var compiledTag = $compile(tag)(scope);
                        angular.element("#tagContainer").append(compiledTag);
                    }

                    function updateSuccess(){
                        var uploadLoading = angular.element('.col-md-9');
                        uploadLoading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        scope.hideEditImageModal();
                        $('.panel .alert-success').fadeIn(500, function (e) {
                          $(this).fadeOut(3000);
                        });
                        setTimeout(function() { 
                            ContentsService.getContentById(rootScope.moduleOptions.contentId, '1').then(function () {
                                $state.reload();
                            });
                        }, 2000);
                    }
                },
                templateUrl: '/vgn-ext-templating/beg/jsp/directives-templates/module-options.html'
            };
}]);

angular.module(moduleName)
    .directive('ngFileModel', ['$parse', '$http', '$rootScope','hyattEditConfiguration', 'UtilInlineService', function($parse, $http, rootScope, hyattEditConfiguration, UtilInlineService) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var model = $parse(attrs.ngFileModel);
                var forceStaticFile = attrs.forceStaticfile;
                var isMultiple = attrs.multiple;
                var fileType = attrs.ngFileModel;
                var isEdit = attrs.isEdit;
                var isResource = attrs.isResource;
                var loading;

                var modelSetter = model.assign;
                element.bind('change', function() {
                    var file = element[0].files[0];
                    if(rootScope.isDropEvent != undefined) {
                        file = rootScope.dropFiles[0];
                        delete rootScope.dropFiles;
                        delete rootScope.isDropEvent;
                    } 
                    file.extension = "pdf";

                    var fileReader = new FileReader();
                    fileReader.onload = function (e) {
                        var data = e.target.result;
                        rootScope.imageObject = {};
                        rootScope.imageObject.filename = file.name.toLowerCase().replace(/([\.])/gi, '_' + new Date().getTime() + '.');
                        rootScope.imageObject.mimeType = file.type;
                        rootScope.imageObject.imageBytes = data;
                        rootScope.imageObject.logicalPath = UtilInlineService.pathToSave();
                        if(file.type.indexOf("image") !== -1) {
                            rootScope.imageObject.imagePathValue = UtilInlineService.pathToSave();
                            rootScope.imageObject.forceStaticFile = true;
                        } else {
                            rootScope.imageObject.logicalPath = UtilInlineService.pathToSave();
                            rootScope.imageObject.forceStaticFile = false;
                        }
    
                        angular.element(".browseFile").val(null);
                        //behaviour when adding button
                        if(isEdit === "false"){
                            angular.element(".bt-add-attac").addClass("ng-hide");
                            angular.element(".add-attac").removeClass("ng-hide");
                        }
                        
                        //behaviour when editing button
                         else {
                            angular.element(".bt-edit-attac").addClass("ng-hide");
                            angular.element(".edit-attac").removeClass("ng-hide");
                        }

                        rootScope.fileName = rootScope.imageObject.filename;
                        rootScope.$apply();

                        if(isResource !== "true") {
                            loading.LoadingOverlay("hide", true);
                        }
                    };

                    if(file){
                        if(isResource === "true") {
                            angular.element(".resource-stepper__content__files").removeClass("ng-hide");
                            angular.element(".resource-stepper__content__select-file").addClass("ng-hide");
                            angular.element(".next-button").prop("disabled", false);
                        } else {
                            if(isEdit === "false"){
                                loading = angular.element('.file-upload');
                            } else {
                                loading = angular.element('.modal-content');
                            }
                            loading.LoadingOverlay("show", { image: hyattEditConfiguration.default.paths.imageLoaing, zIndex: 100000 });
                        }
                        
                        fileReader.readAsDataURL(file);
                    }
                });
            }
        };
    }]);
angular.module(moduleName)
    .directive('onFinishRender', function ($timeout) {
            return {
                restrict: 'A',
                scope: {
                    'moduleId': '=moduleId'
                },
                link: function (scope, element, attrs) {
                    $timeout(function () {
                        $(".type-4-"+ scope.moduleId +" .img-container").each(function () {
                            var $container = $(this),
                            imgUrl = $container.find("img").prop("src");
                            if (imgUrl) {
                              $container.css("background", "url('" + imgUrl + "')").addClass("object-fit-type-4");
                              $container.find("img").css("opacity","0");
                            }
                        });

                        $(".type-3-"+ scope.moduleId +" .img-container").each(function () {
                            var $container = $(this),
                            imgUrl = $container.find("img").prop("src");
                            if (imgUrl) {
                              $container.css("background", "url('" + imgUrl + "')").addClass("object-fit-type-3");
                              $container.find("img").css("opacity","0");
                            }
                        });
                    },500);
                }
            };
});

angular.module(moduleName).
  factory('UtilInlineService', UtilInlineService);

function UtilInlineService() {
  var api;
  api = {
    decode: function (text) {
      var elem = document.createElement('textarea');
      elem.innerHTML = text;
      return elem.value;
    },
    isNotLogged: function (responseData) {
      var xmlString = responseData;
      var parser = new DOMParser();
      var doc = parser.parseFromString(xmlString, "text/html");
      var bodySiteLogin = $(doc).find('.bodySiteLogin');
      return bodySiteLogin.length > 0;
    },
    pathToSave: function () {
      var url = window.location.href;
      if(url.indexOf("serviceportal") != -1) {
        return "/MiniSites/ServicePortal/Assets/";
      } else {
        var name = url.split("/")[7];
        if(name === "WorldofHyatt"){
            name = 'World of Hyatt';
        } else if(name === "HyattPlace"){
            name = 'Hyatt Place';
        } else if(name === "HyattHouse"){
            name = 'Hyatt House';
        } else if(name === "HyattZilara"){
            name = 'Hyatt Zilara';
        } else if(name === "HyattZiva"){
            name = 'Hyatt Ziva';
        } else if(name === "HyattResidenceClub"){
            name = 'Hyatt Residence Club';
        } else if(name === "HyattCentric"){
            name = 'Hyatt Centric';
        } else if(name === "ParkHyatt"){
            name = 'Park Hyatt';
        } else if(name === "GrandHyatt"){
            name = 'Grand Hyatt';
        }  else if(name === "HyattRegency"){
            name = 'Hyatt Regency';
        }  else if(name === "TheUnboundCollection"){
            name = 'The Unbound Collection';
        } else if(name === "JoiedeVivre"){
            name = 'Joie de Vivre';
        }
        return '/BEG/Assets/' + name + '/';
      }
    },
    getChaptersId: function(){
      var list = angular.element(".chapter-item");
      var chapters = [];
      for (var i = 0; i < list.length; i++) {
        var id = angular.element(list[i]).attr("id").replace("menu-item-","");
        chapters.push(id);
      }
      return chapters;
    },
  };
  return api;
}

angular.module(moduleName)
.controller('editController', ['$scope', 'ContentsService', 'ContentsEditModuleService', '$location', '$timeout', '$state', 'hyattEditConfiguration',
    function (scope, ContentsService, ContentsEditModuleService, $location, $timeout, $state, hyattEditConfiguration) {

		scope.clearCacheModules = function (id) {
			ContentsService.getContentById(id,"1");
		};
}]);
