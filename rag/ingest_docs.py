import os 
from pypdf import PdfReader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
import uuid


class Config:
    INPUT_FOLDER = r"../data/documents"
    EMBEDDING_MODEL = "BAAI/bge-base-en-v1.5"
    QDRANT_URL = "http://localhost:6333"
    COLLECTION_NAME = "Vector_collection_cyber_docs"



class DocumentIngestor:
    
    """
    Class to ingest documents and store them into qdrant vector database.
    
    """

    def __init__(self):
        self.INPUT_FOLDER = Config.INPUT_FOLDER
        self.COLLECTION_NAME = Config.COLLECTION_NAME
        self.embedder = SentenceTransformer(Config.EMBEDDING_MODEL)
        self.qdrant = QdrantClient(url=Config.QDRANT_URL)
        self.text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        length_function=len
        )
    
    
    ## read in each docuemnts data store as key : value pair document name : text
    def extractText(self):
        """
        The text splitter we use later for .create_documents requires 1 long string not an array
        therfore here we have an array of text page numbner combos we will break down later
        """
        data_dict = {}
        for filepath in os.listdir(self.INPUT_FOLDER):
            filepath = os.path.join(self.INPUT_FOLDER, filepath)
            with(open(filepath, "r") as f):
                reader = PdfReader(filepath)
                filename = os.path.basename(filepath)
                texts = []
                for page_number, page in enumerate(reader.pages):
                    texts.append({"text": page.extract_text(), "page_number": page_number + 1})
                    #print(str({texts[0]["text"]}), int(texts[0]["page_number"]))
                data_dict[filename] = texts ## each file has entry of text: texts, pagenum: number
                    
        
        return data_dict
                
    
    def chunk_docs(self, dictionary: dict[str, dict[str, int]]):
        """
        Langhchain expects list of length 1 with a string, if we pass just data to create_documents it 
        treats data as an intterable so hello = ['h', 'e', 'l', 'l', 'o'].
        """
        total_chunks = []
        for filename, data in dictionary.items(): 
            for entry in data:
                text = str(entry["text"])
                page_number = int(entry["page_number"])                
                chunks = self.text_splitter.create_documents(
                    texts=[entry["text"]], 
                    metadatas=[{"source": filename, "page_number": page_number}])
                total_chunks.extend(chunks)
        
        return total_chunks
    
    
    def create_qdrant_collection(self):
        """Create a collection to store the vector data
        """
        if self.qdrant.collection_exists(collection_name=self.COLLECTION_NAME):
            print(f"collection {self.COLLECTION_NAME} already exists")
            return
        
        self.qdrant.create_collection(
            collection_name=self.COLLECTION_NAME,
            vectors_config=VectorParams(size=768, distance=Distance.DOT) # since our embeddingsa model is 768 dimensional vectors
        )
        
        
    
    def create_embeddings(self, chunks_dataset):
        """
        Create the embeddings which we store with the meta data of that chunk into a "point". "points" are the central entity
        that Qdrant operates with according to their website. A point consits of a vector and optional payload

        Args:
            chunks (array of langchain document structures): contains chunks of text with meta data of filename and pagenumber for each chunk
            chunk[0].page_content is the chunk of text
            chunk[0].metadata["page_number"] is page num of chunk and 
            chunk[0].metadata["source"] is the filename
        """
        

        ## extract all chunks into sublist
        ## get vector output for sublist
        ## itterate over chunks
        # for each chunk we get the page num the source, the page content and the vector embedding
        # into qdrant db we store payload as page content (chunk text), page number, document source and the vector as the vector
        chunks = [chunk.page_content for chunk in chunks_dataset]
        vectors = self.embedder.encode(chunks)
        points=[]
        
        ## for every chunk we create an array of pointstructs with the ID, vector, and payload
        points = [ PointStruct(id = uuid.uuid4(),
                               vector = vectors[index], 
                               payload={
                                   "chunksource": chunk.metadata["source"], 
                                    "pagenumber": chunk.metadata["page_number"], 
                                    "chunktext": chunk.page_content
                                }) for index, chunk in enumerate(chunks_dataset)]
       
    
                
        operation_info = self.qdrant.upsert(
            collection_name=self.COLLECTION_NAME,
            wait=True,
            points=points,
        )
        
        print(operation_info)
        
        
        
class RagAgent:
    def __init__(self):
        self.INPUT_FOLDER = Config.INPUT_FOLDER
        self.embedder = SentenceTransformer(Config.EMBEDDING_MODEL)
        self.qdrant = QdrantClient(url=Config.QDRANT_URL)
        self.COLLECTION_NAME = Config.COLLECTION_NAME

        
    def retrieve_chunks(self, query: str):
        
        Query_vector = self.embedder.encode(query)
        
        search_result = self.qdrant.query_points(
            collection_name=self.COLLECTION_NAME,
            query=Query_vector,
            with_payload=True,
            limit=3
        ).points

        for point in search_result:
            print(point.score)
            print(point.payload, "\n")
        
        ## get query as vector using embeddings of user query / question
        ## collection name
        # top_k, how many results back
    
        # search results store as list of scorepoint objects
            # has .score and .payload
            # this returns the chunks we use as context when calling thje LLM, this is the retreival
        
        
                
        
def main():
    document_ingestor = DocumentIngestor()
    Dictionary = document_ingestor.extractText()
    Chunks = document_ingestor.chunk_docs(Dictionary)
    
    for var in Chunks:
        print(f"\n, {var.page_content} at page {var.metadata["page_number"]}")
        break
    
    document_ingestor.create_qdrant_collection()
    document_ingestor.create_embeddings(Chunks)
    
    
    print(f"vector DB created") 


    
if __name__ == "__main__":
    main()
    