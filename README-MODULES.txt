There are a ridiculous number of modules because 1) one of my
pet peeves is projects that unnecessarily force you to use a
particular library (hence the APIs) and 2) it's easier to combine
several related modules than to tease apart one so you only
pull in what you want or need.

Hence the modules:

1) cryptographic modules split because of export/import laws:
cryptographic API + bouncy castle implementation.

2) persistence modules split because it's perfectly reasonable
to use either a NoSQL or traditional database to store certificates:
persistence API, NoSQL implementation, traditional JPA/Hibernate
implementation.

3) business logic modules split to reflect the architecture
discussed in the appropriate RFCs: registration authority, certificate
authority and repository.

4) presentation layer modules that separate the presentation
from the business logic.
