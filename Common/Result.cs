using System;


namespace ApiAutenticacao.common
{
    public class Result
    {
        public bool IsSucess { get; }
        public bool ISFailure => !IsSucess;
        public Error Error { get; }
    

    protected Result(bool isSucess, Error error)
        {
            if (isSucess && error != Error.None)
            throw new InvalidOperationException("Um resultado de sucesso não pode conter um erro.");

            if (!isSucess && error == Error.None)
                throw new InvalidOperationException("Um resultado de falha deve conter um erro.");

            IsSucess = isSucess;
            Error = error;
        }

    
    public static Result Sucess() => new(true, Error.None);
    public static Result Failure(Error error) => new(false, error);

        internal static Result Success()
        {
            throw new NotImplementedException();
        }
    }


// padrao result generico para encapsular o valor de retorno e o estado do resultado (sucesso ou falha).
public class Result<T> : Result
    {
      private readonly T? _value;
        
        // Propriedade que retorna o valor encapsulado se o resultado for de sucesso; caso contrário, lança uma exceção.
      public T Value => IsSucess 
        ? _value! 
        : throw new InvalidOperationException("Não é possível acessar o valor de um resultado com falha.");

      protected internal Result(T? value, bool isSucess, Error error) : base(isSucess, error)
      {
          _value = value;
      }
      
      public static Result<T> Success(T value) => new(value, true, Error.None);
      public static new Result<T> Failure(Error error) => new(default, false, error);
    }
}