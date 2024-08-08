using System.IO;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace AccountProvider
{
    public class Function
    {
        private readonly ILogger<Function> _logger;

        public Function(ILogger<Function> logger)
        {
            _logger = logger;
        }

        [Function("ProcessBlobViaHttpTrigger")]
        public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequestData req)
        {
            string blobName = "samples-workitems/sample.txt";  // Example blob name
            string connectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");

            var blobClient = new BlobClient(connectionString, "samples-workitems", blobName);

            BlobDownloadInfo download = await blobClient.DownloadAsync();

            string content; // Declare content variable here

            using (var reader = new StreamReader(download.Content))
            {
                content = await reader.ReadToEndAsync();
            }

            _logger.LogInformation($"Blob content: {content}");

            var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
            response.WriteString($"Blob content: {content}");
            return response;
        }
    }
}
