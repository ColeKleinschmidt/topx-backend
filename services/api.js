//fetch("https://www.mediawiki.org/w/api.php")
async function getWikiData(articleTitle) 
{
    const apiUrl = `https://en.wikipedia.org/w/api.php?action=query&titles=${encodeURIComponent(articleTitle)}&prop=pageimages|extracts&format=json&pithumbsize=500&exintro=1&explaintext=1`;

    try 
    {
        const response = await fetch(apiUrl);
        if (!response.ok) 
        {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();

        const pages = data.query.pages;
        const page = Object.values(pages)[0];

        const articleUrl = `https://en.wikipedia.org/?curid=${page.pageid}`;
        console.log("Wikipedia URL:", articleUrl);

        if (page)
        {
            console.log("Thumbnail URL:", page.thumbnail.source);
        }

        else
        {
            console.log("No thumbnail found for this article.");
        }

        if (page.extract)
        {
            const firstSentence = page.extract.split(". ")[0] + '.';
            console.log("First sentence:", firstSentence);
        }

        else
        {
            console.log("No extract found for this article.");
        }
    }
    catch (error) 
    {
        console.error("Error fetching Wikipedia page data:", error.message);
    }
}

getWikiData('Bean');