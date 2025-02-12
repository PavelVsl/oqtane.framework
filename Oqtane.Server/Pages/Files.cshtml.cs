using System;
using System.IO;
using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Oqtane.Enums;
using Oqtane.Extensions;
using Oqtane.Infrastructure;
using Oqtane.Models;
using Oqtane.Repository;
using Oqtane.Security;
using Oqtane.Shared;

namespace Oqtane.Pages
{
    [AllowAnonymous]
    public class FilesModel : PageModel
    {
        private readonly IWebHostEnvironment _environment;
        private readonly IFileRepository _files;
        private readonly IUserPermissions _userPermissions;
        private readonly IUrlMappingRepository _urlMappings;
        private readonly ILogManager _logger;
        private readonly Alias _alias;

        public FilesModel(IWebHostEnvironment environment, IFileRepository files, IUserPermissions userPermissions, IUrlMappingRepository urlMappings, ILogManager logger, ITenantManager tenantManager)
        {
            _environment = environment;
            _files = files;
            _userPermissions = userPermissions;
            _urlMappings = urlMappings;
            _logger = logger;
            _alias = tenantManager.GetAlias();
        }

        public IActionResult OnGet(string path)
        {
            path = path.Replace("\\", "/");
            var folderpath = "";
            var filename = "";

            var segments = path.Split('/');
            if (segments.Length > 0)
            {
                filename = segments[segments.Length - 1].ToLower();
                if (segments.Length > 1)
                {
                    folderpath = string.Join("/", segments, 0, segments.Length - 1).ToLower() + "/";
                }
            }

            var file = _files.GetFile(_alias.SiteId, folderpath, filename);
            if (file != null)
            {
                if (_userPermissions.IsAuthorized(User, PermissionNames.View, file.Folder.Permissions))
                {
                    var filepath = _files.GetFilePath(file);
                    if (System.IO.File.Exists(filepath))
                    {
                        return PhysicalFile(filepath, file.GetMimeType());
                    }
                    else
                    {
                        _logger.Log(LogLevel.Error, this, LogFunction.Read, "File Does Not Exist {FilePath}", filepath);
                        HttpContext.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    }
                }
                else
                {
                    _logger.Log(LogLevel.Error, this, LogFunction.Security, "Unauthorized File Access Attempt {SiteId} {Path}", _alias.SiteId, path);
                    HttpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                }
            }
            else
            {
                // look for url mapping
                var urlMapping = _urlMappings.GetUrlMapping(_alias.SiteId, "files/" + folderpath + filename);
                if (urlMapping != null && !string.IsNullOrEmpty(urlMapping.MappedUrl))
                {
                    var url = urlMapping.MappedUrl;
                    if (!url.StartsWith("http"))
                    {
                        var uri = new Uri(HttpContext.Request.GetEncodedUrl());
                        url = uri.Scheme + "://" + uri.Authority + ((!string.IsNullOrEmpty(_alias.Path)) ? "/" + _alias.Path : "") + "/" + url;
                    }
                    return RedirectPermanent(url);
                }
            }

            // broken link
            string errorPath = Path.Combine(Utilities.PathCombine(_environment.ContentRootPath, "wwwroot\\images"), "error.png");
            return PhysicalFile(errorPath, MimeUtilities.GetMimeType(errorPath));
        }
    }
}
